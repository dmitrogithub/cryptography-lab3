"""Integration tests for the four compiled Vershyna file tools.

Run from any directory with ``python lr3/tests/test_cli.py`` after build.ps1.
Only the Python standard library is needed. Every generated file stays in a
temporary directory inside lr3 and is removed after the tests.
"""

from __future__ import annotations

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct("<4sBBBBQ")
PUBLIC_KEY, PRIVATE_KEY, DETACHED, ATTACHED = 1, 2, 3, 4
SIZES = {
    1: (1472, 3488, 2693),
    2: (2624, 5792, 5345),
    3: (4528, 9088, 6762),
    4: (5824, 11008, 10708),
}
BINARY_MESSAGE = bytes(range(256)) * 3 + b"\x00\xff\r\nVershyna\x00\x80"


def program(mode: int) -> Path:
    name = "lab3" if mode == 1 else f"lab3-mode{mode}"
    windows = ROOT / "bin" / f"{name}.exe"
    return windows if windows.exists() else ROOT / "bin" / name


def invoke(mode: int, *args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(program(mode)), *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )


def option(name: str, value: object) -> str:
    return f"--{name}={value}"


def generate_args(public: Path, private: Path) -> tuple[str, ...]:
    return (
        "--command=generate",
        option("public-key", public),
        option("private-key", private),
    )


def sign_args(
    message: Path,
    private: Path,
    output: Path,
    kind: str = "detached",
    signing: str = "deterministic",
) -> tuple[str, ...]:
    return (
        "--command=sign",
        option("file", message),
        option("private-key", private),
        option("type", kind),
        option("signing", signing),
        option("out", output),
    )


def verify_args(
    message: Path,
    public: Path,
    signature: Path | None = None,
    *,
    output: Path | None = None,
) -> tuple[str, ...]:
    result = (
        "--command=verify",
        option("file", message),
        option("public-key", public),
        option("type", "attached" if signature is None else "detached"),
    )
    if signature is not None:
        result += (option("signature", signature),)
    if output is not None:
        result += (option("out", output),)
    return result


class FileCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        missing = [str(program(mode)) for mode in SIZES if not program(mode).is_file()]
        if missing:
            raise RuntimeError("Build all four modes before running tests: " + ", ".join(missing))
        cls.temporary = tempfile.TemporaryDirectory(prefix="lab3-tests-", dir=ROOT)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.fixtures: dict[int, dict[str, Path]] = {}
        for mode in SIZES:
            directory = cls.base / f"mode{mode}"
            directory.mkdir()
            paths = {
                "message": directory / "message.bin",
                "public": directory / "public.vsl3",
                "private": directory / "private.vsl3",
                "detached": directory / "message.sig",
                "attached": directory / "message.signed",
            }
            paths["message"].write_bytes(BINARY_MESSAGE)
            calls = [
                generate_args(paths["public"], paths["private"]),
                sign_args(paths["message"], paths["private"], paths["detached"]),
                sign_args(paths["message"], paths["private"], paths["attached"], "attached"),
            ]
            for args in calls:
                result = invoke(mode, *args)
                if result.returncode != 0:
                    raise RuntimeError(
                        f"Fixture command for mode {mode} failed ({result.returncode}):\n"
                        f"{result.stdout}\n{result.stderr}"
                    )
            cls.fixtures[mode] = paths

    def setUp(self) -> None:
        self.work = self.base / self._testMethodName
        self.work.mkdir()
        self.files = self.fixtures[1]

    def run_cli(self, mode: int, expected: int, *args: object) -> subprocess.CompletedProcess[str]:
        result = invoke(mode, *args)
        self.assertEqual(
            result.returncode,
            expected,
            f"mode={mode}, args={args!r}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def assert_container(self, path: Path, mode: int, kind: int, length: int) -> bytes:
        data = path.read_bytes()
        self.assertGreaterEqual(len(data), HEADER.size)
        self.assertEqual(HEADER.unpack(data[: HEADER.size]), (b"VSL3", 1, mode, kind, 0, length))
        self.assertEqual(len(data), HEADER.size + length)
        return data[HEADER.size :]

    def test_help_and_no_arguments_for_all_modes(self) -> None:
        for mode in SIZES:
            for args in [(), ("--help",)]:
                with self.subTest(mode=mode, args=args):
                    result = self.run_cli(mode, 0, *args)
                    for command in ("generate", "sign", "verify"):
                        self.assertIn(command, result.stdout.lower())

    def test_all_key_and_signature_container_headers(self) -> None:
        for mode, (public_size, private_size, signature_size) in SIZES.items():
            files = self.fixtures[mode]
            with self.subTest(mode=mode):
                self.assert_container(files["public"], mode, PUBLIC_KEY, public_size)
                self.assert_container(files["private"], mode, PRIVATE_KEY, private_size)
                signature = self.assert_container(files["detached"], mode, DETACHED, signature_size)
                attached = self.assert_container(
                    files["attached"], mode, ATTACHED, len(BINARY_MESSAGE) + signature_size
                )
                self.assertEqual(attached, BINARY_MESSAGE + signature)

    def test_binary_detached_and_attached_roundtrip_in_all_modes(self) -> None:
        for mode in SIZES:
            files = self.fixtures[mode]
            recovered = self.work / f"recovered-{mode}.bin"
            with self.subTest(mode=mode, kind="detached"):
                self.run_cli(
                    mode, 0, *verify_args(files["message"], files["public"], files["detached"])
                )
            with self.subTest(mode=mode, kind="attached"):
                self.run_cli(mode, 0, *verify_args(files["attached"], files["public"]))
                self.run_cli(
                    mode, 0, *verify_args(files["attached"], files["public"], output=recovered)
                )
                self.assertEqual(recovered.read_bytes(), BINARY_MESSAGE)

    def test_empty_files_and_unicode_paths(self) -> None:
        directory = self.work / "Підписані файли з пробілами"
        directory.mkdir()
        public = directory / "відкритий ключ.vsl3"
        private = directory / "особистий ключ.vsl3"
        self.run_cli(1, 0, *generate_args(public, private))
        messages = {
            "порожній файл.bin": b"",
            "повідомлення є ї ґ.txt": "Привіт, Україно!\r\nСимволи: є ї ґ.\n".encode("utf-8"),
        }
        for index, (name, data) in enumerate(messages.items()):
            message = directory / name
            message.write_bytes(data)
            for kind in ("detached", "attached"):
                with self.subTest(name=name, kind=kind):
                    signature = directory / f"підпис {index} {kind}.vsl3"
                    self.run_cli(1, 0, *sign_args(message, private, signature, kind))
                    if kind == "detached":
                        self.run_cli(1, 0, *verify_args(message, public, signature))
                        self.assert_container(signature, 1, DETACHED, SIZES[1][2])
                    else:
                        recovered = directory / f"відновлений {index}.bin"
                        self.run_cli(1, 0, *verify_args(signature, public, output=recovered))
                        self.assertEqual(recovered.read_bytes(), data)
                        self.assert_container(signature, 1, ATTACHED, len(data) + SIZES[1][2])

    def test_deterministic_signatures_repeat_in_all_modes(self) -> None:
        for mode in SIZES:
            files = self.fixtures[mode]
            repeated = self.work / f"deterministic-{mode}.vsl3"
            with self.subTest(mode=mode):
                self.run_cli(mode, 0, *sign_args(files["message"], files["private"], repeated))
                self.assertEqual(repeated.read_bytes(), files["detached"].read_bytes())

    def test_randomized_signatures_differ_and_verify_in_all_modes(self) -> None:
        for mode in SIZES:
            files = self.fixtures[mode]
            signatures = [self.work / f"random-{mode}-{index}.vsl3" for index in range(2)]
            with self.subTest(mode=mode):
                for signature in signatures:
                    self.run_cli(
                        mode,
                        0,
                        *sign_args(files["message"], files["private"], signature, signing="randomized"),
                    )
                    self.run_cli(mode, 0, *verify_args(files["message"], files["public"], signature))
                self.assertNotEqual(signatures[0].read_bytes(), signatures[1].read_bytes())

    def test_changed_message_and_public_key_fail_verification(self) -> None:
        altered_message = self.work / "changed.bin"
        altered_message.write_bytes(bytes([BINARY_MESSAGE[0] ^ 1]) + BINARY_MESSAGE[1:])
        self.run_cli(
            1, 1, *verify_args(altered_message, self.files["public"], self.files["detached"])
        )

        other_public = self.work / "other-public.vsl3"
        other_private = self.work / "other-private.vsl3"
        self.run_cli(1, 0, *generate_args(other_public, other_private))
        self.run_cli(
            1, 1, *verify_args(self.files["message"], other_public, self.files["detached"])
        )

        altered_public = self.work / "changed-public.vsl3"
        data = bytearray(self.files["public"].read_bytes())
        data[HEADER.size] ^= 1
        altered_public.write_bytes(data)
        self.run_cli(
            1, 1, *verify_args(self.files["message"], altered_public, self.files["detached"])
        )

    def test_changed_detached_signature_fails_verification(self) -> None:
        altered = self.work / "changed-signature.vsl3"
        data = bytearray(self.files["detached"].read_bytes())
        data[HEADER.size] ^= 1
        altered.write_bytes(data)
        self.run_cli(1, 1, *verify_args(self.files["message"], self.files["public"], altered))

    def test_failed_attached_verification_never_extracts(self) -> None:
        original = self.files["attached"].read_bytes()
        for name, offset in [("message", HEADER.size), ("signature", HEADER.size + len(BINARY_MESSAGE))]:
            with self.subTest(tampered=name):
                changed = bytearray(original)
                changed[offset] ^= 1
                altered = self.work / f"changed-{name}.vsl3"
                altered.write_bytes(changed)
                recovered = self.work / f"recovered-{name}.bin"
                self.run_cli(1, 1, *verify_args(altered, self.files["public"], output=recovered))
                self.assertFalse(recovered.exists())

    @staticmethod
    def malformed_variants(original: bytes) -> dict[str, bytes]:
        variants: dict[str, bytes] = {}
        for name, offset, value in [
            ("magic", 0, ord("X")),
            ("version", 4, 2),
            ("mode", 5, 2),
            ("zero-mode", 5, 0),
            ("type", 6, 255),
            ("reserved", 7, 1),
        ]:
            data = bytearray(original)
            data[offset] = value
            variants[name] = bytes(data)
        length = struct.unpack_from("<Q", original, 8)[0]
        for name, length_value in [
            ("length-short", length - 1),
            ("length-long", length + 1),
            ("length-overflow", (1 << 64) - 1),
        ]:
            data = bytearray(original)
            struct.pack_into("<Q", data, 8, length_value)
            variants[name] = bytes(data)
        variants["empty"] = b""
        variants["short-header"] = original[: HEADER.size - 1]
        variants["truncated-payload"] = original[:-1]
        variants["trailing-data"] = original + b"\x00"
        wrong_size = bytearray(original[:-1])
        struct.pack_into("<Q", wrong_size, 8, length - 1)
        if original[6] == ATTACHED:
            wrong_size = bytearray(original[: HEADER.size + SIZES[1][2] - 1])
            struct.pack_into("<Q", wrong_size, 8, SIZES[1][2] - 1)
        variants["self-consistent-wrong-size"] = bytes(wrong_size)
        return variants

    def test_malformed_containers_are_errors_and_never_extract(self) -> None:
        for kind in ("public", "private", "detached", "attached"):
            for variant, data in self.malformed_variants(self.files[kind].read_bytes()).items():
                with self.subTest(kind=kind, malformed=variant):
                    malformed = self.work / f"{kind}-{variant}.vsl3"
                    malformed.write_bytes(data)
                    output = self.work / f"output-{kind}-{variant}.bin"
                    if kind == "public":
                        args = verify_args(self.files["message"], malformed, self.files["detached"])
                    elif kind == "private":
                        args = sign_args(self.files["message"], malformed, output)
                    elif kind == "detached":
                        args = verify_args(self.files["message"], self.files["public"], malformed)
                    else:
                        args = verify_args(malformed, self.files["public"], output=output)
                    self.run_cli(1, 2, *args)
                    self.assertFalse(output.exists())

    def test_wrong_container_types_are_rejected(self) -> None:
        cases = [
            verify_args(self.files["message"], self.files["private"], self.files["detached"]),
            verify_args(self.files["message"], self.files["public"], self.files["attached"]),
            verify_args(self.files["detached"], self.files["public"]),
            sign_args(self.files["message"], self.files["public"], self.work / "bad-signature.vsl3"),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.run_cli(1, 2, *args)
        self.assertFalse((self.work / "bad-signature.vsl3").exists())

    def test_other_modes_are_rejected(self) -> None:
        for mode in (2, 3, 4):
            other = self.fixtures[mode]
            cases = [
                verify_args(self.files["message"], other["public"], self.files["detached"]),
                verify_args(self.files["message"], self.files["public"], other["detached"]),
                sign_args(self.files["message"], other["private"], self.work / f"bad-{mode}.vsl3"),
                verify_args(other["attached"], self.files["public"]),
            ]
            for args in cases:
                with self.subTest(mode=mode, args=args):
                    self.run_cli(1, 2, *args)
            self.assertFalse((self.work / f"bad-{mode}.vsl3").exists())

    def test_existing_outputs_are_preserved(self) -> None:
        sentinel = b"Keep this existing output exactly.\x00\xff"
        for label, key in [("public", "public"), ("private", "private")]:
            existing = self.work / f"existing-{label}.vsl3"
            existing.write_bytes(sentinel)
            other = self.work / f"new-{label}.vsl3"
            public, private = (existing, other) if key == "public" else (other, existing)
            with self.subTest(command="generate", existing=label):
                self.run_cli(1, 2, *generate_args(public, private))
                self.assertEqual(existing.read_bytes(), sentinel)
                self.assertFalse(other.exists())

        output = self.work / "existing-signature.vsl3"
        output.write_bytes(sentinel)
        self.run_cli(1, 2, *sign_args(self.files["message"], self.files["private"], output))
        self.assertEqual(output.read_bytes(), sentinel)

        recovered = self.work / "existing-recovered.bin"
        recovered.write_bytes(sentinel)
        self.run_cli(1, 2, *verify_args(self.files["attached"], self.files["public"], output=recovered))
        self.assertEqual(recovered.read_bytes(), sentinel)

    def test_colliding_input_and_output_paths_are_preserved(self) -> None:
        for name in ("message", "private"):
            source = self.work / f"{name}.bin"
            before = self.files[name].read_bytes()
            source.write_bytes(before)
            message = source if name == "message" else self.files["message"]
            private = source if name == "private" else self.files["private"]
            with self.subTest(command="sign", input=name):
                self.run_cli(1, 2, *sign_args(message, private, source))
                self.assertEqual(source.read_bytes(), before)

        attached = self.work / "attached.vsl3"
        before = self.files["attached"].read_bytes()
        attached.write_bytes(before)
        self.run_cli(1, 2, *verify_args(attached, self.files["public"], output=attached))
        self.assertEqual(attached.read_bytes(), before)

        shared = self.work / "both-keys.vsl3"
        self.run_cli(1, 2, *generate_args(shared, shared))
        self.assertFalse(shared.exists())

    def test_duplicate_unknown_missing_and_conflicting_arguments(self) -> None:
        output = self.work / "never-created.vsl3"
        sign = sign_args(self.files["message"], self.files["private"], output)
        verify = verify_args(self.files["message"], self.files["public"], self.files["detached"])
        cases = {
            "unknown-command": ("--command=unknown",),
            "unknown-option": sign + ("--unknown=1",),
            "positional-argument": sign + ("unexpected",),
            "duplicate-command": sign + ("--command=sign",),
            "conflicting-command": sign + ("--command=verify",),
            "duplicate-file": sign + (option("file", self.files["message"]),),
            "duplicate-output": sign + (option("out", output),),
            "missing-command": sign[1:],
            "missing-input": tuple(arg for arg in sign if not arg.startswith("--file=")),
            "missing-private-key": tuple(arg for arg in sign if not arg.startswith("--private-key=")),
            "missing-sign-output": tuple(arg for arg in sign if not arg.startswith("--out=")),
            "missing-sign-type": tuple(arg for arg in sign if not arg.startswith("--type=")),
            "missing-signing-method": tuple(arg for arg in sign if not arg.startswith("--signing=")),
            "missing-public-key": tuple(arg for arg in verify if not arg.startswith("--public-key=")),
            "missing-verify-type": tuple(arg for arg in verify if not arg.startswith("--type=")),
            "missing-detached-signature": tuple(arg for arg in verify if not arg.startswith("--signature=")),
            "unknown-type": tuple("--type=unknown" if arg.startswith("--type=") else arg for arg in sign),
            "unknown-signing": tuple(
                "--signing=unknown" if arg.startswith("--signing=") else arg for arg in sign
            ),
            "empty-input-value": tuple("--file=" if arg.startswith("--file=") else arg for arg in sign),
            "option-without-value": ("--command",),
            "generate-with-sign-option": generate_args(self.work / "pub", self.work / "priv")
            + ("--type=detached",),
            "sign-with-public-key": sign + (option("public-key", self.files["public"]),),
            "verify-with-private-key": verify + (option("private-key", self.files["private"]),),
            "verify-with-signing": verify + ("--signing=deterministic",),
            "attached-with-separate-signature": verify_args(self.files["attached"], self.files["public"])
            + (option("signature", self.files["detached"]),),
            "detached-with-extraction": verify + (option("out", output),),
        }
        for label, args in cases.items():
            with self.subTest(case=label):
                self.run_cli(1, 2, *args)
                self.assertFalse(output.exists())

    def test_missing_files_and_output_directories_are_io_errors(self) -> None:
        absent = self.work / "absent.bin"
        output = self.work / "never-created.vsl3"
        cases = [
            sign_args(absent, self.files["private"], output),
            sign_args(self.files["message"], absent, output),
            verify_args(absent, self.files["public"], self.files["detached"]),
            verify_args(self.files["message"], absent, self.files["detached"]),
            verify_args(self.files["message"], self.files["public"], absent),
            sign_args(self.files["message"], self.files["private"], self.work / "absent" / "sig"),
            verify_args(self.files["attached"], self.files["public"], output=self.work / "absent" / "msg"),
            generate_args(self.work / "absent" / "public", self.work / "absent" / "private"),
        ]
        for args in cases:
            with self.subTest(args=args):
                self.run_cli(1, 2, *args)
                self.assertFalse(output.exists())
        self.assertFalse((self.work / "absent").exists())

    def test_separate_option_values(self) -> None:
        public = self.work / "public.vsl3"
        private = self.work / "private.vsl3"
        signature = self.work / "signature.vsl3"
        self.run_cli(1, 0, "--command", "generate", "--public-key", public, "--private-key", private)
        self.run_cli(
            1,
            0,
            "--command",
            "sign",
            "--file",
            self.files["message"],
            "--private-key",
            private,
            "--type",
            "detached",
            "--signing",
            "deterministic",
            "--out",
            signature,
        )
        self.run_cli(
            1,
            0,
            "--command",
            "verify",
            "--file",
            self.files["message"],
            "--public-key",
            public,
            "--type",
            "detached",
            "--signature",
            signature,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
