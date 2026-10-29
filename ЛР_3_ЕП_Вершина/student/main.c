#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <dstu9212/dstu9212.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#define HEADER_BYTES 16U
#define MAX_FILE_BYTES ((uint64_t)256U * 1024U * 1024U)
enum { PUBLIC_KEY = 1, PRIVATE_KEY = 2, DETACHED = 3, ATTACHED = 4 };
enum { SUCCESS = 0, INVALID_SIGNATURE = 1, FAILURE = 2 };

typedef struct {
    const char *command, *file, *public_key, *private_key;
    const char *type, *signing, *out, *signature;
} options;

typedef struct {
    uint8_t *data;
    size_t size;
} buffer;

static void help(void)
{
    printf("Laboratory 3: DSTU 9212 file signatures (VSL3)\n"
           "Mode %d: %s\nPublic key: %zu bytes; private key: %zu bytes; signature: %zu bytes.\n\n",
           DSTU9212_MODE, dstu9212_mode_name(), dstu9212_public_key_bytes(),
           dstu9212_secret_key_bytes(), dstu9212_signature_bytes());
    puts("Usage:\n"
         "  lab3 --help\n"
         "  lab3 --command=generate --public-key=public.vpk --private-key=secret.vsk\n"
         "  lab3 --command=sign --file=message.bin --private-key=secret.vsk\n"
         "       --type=detached --signing=deterministic --out=message.vsig\n"
         "  lab3 --command=sign --file=message.bin --private-key=secret.vsk\n"
         "       --type=attached --signing=randomized --out=message.vsigned\n"
         "  lab3 --command=verify --file=message.bin --public-key=public.vpk\n"
         "       --type=detached --signature=message.vsig\n"
         "  lab3 --command=verify --file=message.vsigned --public-key=public.vpk\n"
         "       --type=attached [--out=recovered.bin]\n\n"
         "Both signature types support deterministic and randomized signing.\n"
         "Options accept --name=value and --name value. Quote paths with spaces.\n"
         "All output paths must be new files. Existing files are never overwritten.\n"
         "Attached payload: original message followed by the fixed-size signature.\n"
         "Recovery is performed only after successful verification.\n"
         "Input file limit: 256 MiB. Keys and signatures must match this build's mode.\n"
         "Exit codes: 0 = success/help, 1 = invalid signature, 2 = other error.");
}

static int argument_error(const char *message)
{
    fprintf(stderr, "Argument error: %s\nUse --help for usage.\n", message);
    return FAILURE;
}

static int parse_options(int argc, char **argv, options *o)
{
    const char *names[] = {
        "command", "file", "public-key", "private-key",
        "type", "signing", "out", "signature"
    };
    const char **fields[] = {
        &o->command, &o->file, &o->public_key, &o->private_key,
        &o->type, &o->signing, &o->out, &o->signature
    };
    size_t field_count = sizeof(names) / sizeof(names[0]);
    int i;
    memset(o, 0, sizeof(*o));
    for (i = 1; i < argc; ++i) {
        const char *name, *value, *equal;
        size_t length, index;
        if (strncmp(argv[i], "--", 2) != 0)
            return argument_error("expected a named option beginning with --");
        name = argv[i] + 2;
        equal = strchr(name, '=');
        length = equal ? (size_t)(equal - name) : strlen(name);
        if (equal) value = equal + 1;
        else {
            if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0)
                return argument_error("missing option value");
            value = argv[++i];
        }
        if (!*value) return argument_error("empty option value");
        for (index = 0; index < field_count; ++index) {
            if (strlen(names[index]) == length &&
                memcmp(name, names[index], length) == 0) break;
        }
        if (index == field_count) return argument_error("unknown option");
        if (*fields[index]) return argument_error("duplicate option");
        *fields[index] = value;
    }
    return SUCCESS;
}

static int validate_options(const options *o)
{
    if (!o->command) return argument_error("--command is required");
    if (strcmp(o->command, "generate") == 0) {
        if (!o->public_key || !o->private_key)
            return argument_error("generate requires --public-key and --private-key");
        if (o->file || o->type || o->signing || o->out || o->signature)
            return argument_error("option is not applicable to generate");
        if (strcmp(o->public_key, o->private_key) == 0)
            return argument_error("public and private keys require different paths");
        return SUCCESS;
    }
    if (strcmp(o->command, "sign") != 0 && strcmp(o->command, "verify") != 0)
        return argument_error("--command must be generate, sign or verify");
    if (!o->file || !o->type)
        return argument_error("--file and --type are required");
    if (strcmp(o->type, "attached") != 0 && strcmp(o->type, "detached") != 0)
        return argument_error("--type must be attached or detached");
    if (strcmp(o->command, "sign") == 0) {
        if (!o->private_key || !o->signing || !o->out)
            return argument_error("sign requires --private-key, --signing and --out");
        if (o->public_key || o->signature)
            return argument_error("option is not applicable to sign");
        if (strcmp(o->signing, "deterministic") != 0 && strcmp(o->signing, "randomized") != 0)
            return argument_error("--signing must be deterministic or randomized");
    } else {
        if (!o->public_key) return argument_error("verify requires --public-key");
        if (o->private_key || o->signing)
            return argument_error("option is not applicable to verify");
        if (strcmp(o->type, "detached") == 0) {
            if (!o->signature) return argument_error("detached verify requires --signature");
            if (o->out) return argument_error("--out is only used for attached recovery");
        } else if (o->signature) return argument_error("attached verify does not use --signature");
    }
    return SUCCESS;
}

#ifdef _WIN32
/* Шляхи з командного рядка зберігаються в UTF-8, Windows приймає UTF-16. */
static wchar_t *wide_path(const char *path)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *w;
    if (!n) { errno = EINVAL; return NULL; }
    w = (wchar_t *)malloc((size_t)n * sizeof(*w));
    if (!w) { errno = ENOMEM; return NULL; }
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, w, n)) {
        free(w); errno = EINVAL; return NULL;
    }
    return w;
}
#endif

static FILE *open_read(const char *path)
{
#ifdef _WIN32
    wchar_t *w = wide_path(path);
    FILE *f;
    if (!w) return NULL;
    f = _wfopen(w, L"rb");
    free(w);
    return f;
#else
    return fopen(path, "rb");
#endif
}

static void remove_owned(const char *path)
{
#ifdef _WIN32
    wchar_t *w = wide_path(path);
    if (w) { _wremove(w); free(w); }
#else
    unlink(path);
#endif
}

static FILE *create_new(const char *path, int secret)
{
    int fd;
    FILE *f;
#ifdef _WIN32
    wchar_t *w = wide_path(path);
    (void)secret;
    if (!w) return NULL;
    fd = _wopen(w, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    free(w);
    if (fd < 0) return NULL;
    f = _fdopen(fd, "wb");
    if (!f) { _close(fd); remove_owned(path); }
#else
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, secret ? 0600 : 0666);
    if (fd < 0) return NULL;
    f = fdopen(fd, "wb");
    if (!f) { close(fd); remove_owned(path); }
#endif
    return f;
}

static void file_error(const char *action, const char *path)
{
    fprintf(stderr, "File error: cannot %s '%s': %s\n", action, path, strerror(errno));
}

static int read_file(const char *path, buffer *b)
{
    FILE *f = open_read(path);
    uint64_t length;
#ifdef _WIN32
    __int64 end;
#else
    off_t end;
#endif
    b->data = NULL; b->size = 0;
    if (!f) { file_error("read", path); return FAILURE; }
#ifdef _WIN32
    if (_fseeki64(f, 0, SEEK_END) != 0 || (end = _ftelli64(f)) < 0 ||
        _fseeki64(f, 0, SEEK_SET) != 0) {
#else
    if (fseeko(f, 0, SEEK_END) != 0 || (end = ftello(f)) < 0 ||
        fseeko(f, 0, SEEK_SET) != 0) {
#endif
        file_error("seek in", path); fclose(f); return FAILURE;
    }
    length = (uint64_t)end;
    if (length > MAX_FILE_BYTES || length > (uint64_t)SIZE_MAX) {
        fprintf(stderr, "File error: '%s' exceeds the 256 MiB input limit.\n", path);
        fclose(f); return FAILURE;
    }
    b->data = (uint8_t *)malloc(length ? (size_t)length : 1U);
    if (!b->data) { fprintf(stderr, "Memory allocation failed.\n"); fclose(f); return FAILURE; }
    b->size = (size_t)length;
    if ((b->size && fread(b->data, 1, b->size, f) != b->size) ||
        fgetc(f) != EOF || ferror(f)) {
        fprintf(stderr, "File error: incomplete read or file changed while reading '%s'.\n", path);
        fclose(f); return FAILURE;
    }
    if (fclose(f) != 0) { file_error("close", path); return FAILURE; }
    return SUCCESS;
}

static void release_buffer(buffer *b, int secret)
{
    if (b->data) {
        if (secret) dstu9212_secure_zero(b->data, b->size);
        free(b->data);
    }
    b->data = NULL; b->size = 0;
}

static uint64_t decode_length(const uint8_t *bytes)
{
    uint64_t value = 0;
    unsigned i;
    for (i = 0; i < 8U; ++i) value |= (uint64_t)bytes[i] << (8U * i);
    return value;
}

static int validate_container(const buffer *b, unsigned type, size_t expected, const char *path)
{
    if (b->size < HEADER_BYTES) {
        fprintf(stderr, "Container error: truncated VSL3 header in '%s'.\n", path);
        return FAILURE;
    }
    if (memcmp(b->data, "VSL3", 4) != 0 || b->data[4] != 1U ||
        b->data[6] != type || b->data[7] != 0U) {
        fprintf(stderr, "Container error: invalid magic, version, object type or reserved byte in '%s'.\n", path);
        return FAILURE;
    }
    if (b->data[5] != DSTU9212_MODE) {
        fprintf(stderr, "Container error: '%s' uses mode %u; this program uses mode %d.\n",
                path, (unsigned)b->data[5], DSTU9212_MODE);
        return FAILURE;
    }
    if (decode_length(b->data + 8) != (uint64_t)(b->size - HEADER_BYTES)) {
        fprintf(stderr, "Container error: payload length does not match file size in '%s'.\n", path);
        return FAILURE;
    }
    if ((type == ATTACHED && b->size - HEADER_BYTES < expected) ||
        (type != ATTACHED && b->size - HEADER_BYTES != expected)) {
        fprintf(stderr, "Container error: incorrect payload size in '%s'.\n", path);
        return FAILURE;
    }
    return SUCCESS;
}

static int write_bytes(FILE *f, const uint8_t *data, size_t size)
{
    return !size || fwrite(data, 1, size, f) == size;
}

static int write_container(FILE *f, unsigned type, const uint8_t *a, size_t a_len,
                           const uint8_t *b, size_t b_len)
{
    uint8_t header[HEADER_BYTES] = { 'V', 'S', 'L', '3', 1, DSTU9212_MODE, 0, 0 };
    uint64_t length = (uint64_t)a_len + (uint64_t)b_len;
    unsigned i;
    header[6] = (uint8_t)type;
    for (i = 0; i < 8U; ++i) header[8U + i] = (uint8_t)(length >> (8U * i));
    return write_bytes(f, header, sizeof(header)) &&
           write_bytes(f, a, a_len) && write_bytes(f, b, b_len);
}

static int close_output(FILE **f)
{
    int ok = fclose(*f) == 0;
    *f = NULL;
    return ok;
}

static int generate(const options *o)
{
    uint8_t pk[DSTU9212_API_PUBLIC_KEY_BYTES];
    uint8_t sk[DSTU9212_API_SECRET_KEY_BYTES];
    FILE *public_file = NULL, *private_file = NULL;
    int own_public = 0, own_private = 0, result = FAILURE;
    puts("[1/3] Creating two new key files.");
    public_file = create_new(o->public_key, 0);
    if (!public_file) { file_error("create", o->public_key); goto cleanup; }
    own_public = 1;
    private_file = create_new(o->private_key, 1);
    if (!private_file) { file_error("create", o->private_key); goto cleanup; }
    own_private = 1;
    puts("[2/3] Generating a DSTU 9212 key pair using system randomness.");
    if (dstu9212_keygen(pk, sk) != DSTU9212_OK) {
        fprintf(stderr, "Key generation failed.\n"); goto cleanup;
    }
    puts("[3/3] Saving the public and private keys in VSL3 containers.");
    if (!write_container(public_file, PUBLIC_KEY, pk, sizeof(pk), NULL, 0) ||
        !write_container(private_file, PRIVATE_KEY, sk, sizeof(sk), NULL, 0)) {
        fprintf(stderr, "Writing key files failed.\n"); goto cleanup;
    }
    if (!close_output(&public_file) || !close_output(&private_file)) {
        fprintf(stderr, "Closing key files failed.\n"); goto cleanup;
    }
    printf("Generated: %s (%zu bytes), %s (%zu bytes).\n", o->public_key,
           sizeof(pk) + HEADER_BYTES, o->private_key, sizeof(sk) + HEADER_BYTES);
    result = SUCCESS;
cleanup:
    if (public_file) fclose(public_file);
    if (private_file) fclose(private_file);
    if (result != SUCCESS) {
        if (own_public) remove_owned(o->public_key);
        if (own_private) remove_owned(o->private_key);
    }
    dstu9212_secure_zero(sk, sizeof(sk));
    return result;
}

static int sign_file(const options *o)
{
    buffer key = { NULL, 0 }, message = { NULL, 0 };
    uint8_t sig[DSTU9212_API_SIGNATURE_BYTES];
    size_t sig_len = 0;
    FILE *output = NULL;
    int own_output = 0, result = FAILURE, written;
    int attached = strcmp(o->type, "attached") == 0;
    dstu9212_status status;
    puts("[1/3] Reading the original file and validating the private-key container.");
    if (read_file(o->private_key, &key) != SUCCESS ||
        validate_container(&key, PRIVATE_KEY, dstu9212_secret_key_bytes(), o->private_key) != SUCCESS ||
        read_file(o->file, &message) != SUCCESS) goto cleanup;
    if (attached && (uint64_t)message.size > MAX_FILE_BYTES - HEADER_BYTES - sizeof(sig)) {
        fprintf(stderr, "File error: attached container would exceed the 256 MiB input limit.\n");
        goto cleanup;
    }
    output = create_new(o->out, 0);
    if (!output) { file_error("create", o->out); goto cleanup; }
    own_output = 1;
    printf("[2/3] Signing %zu original bytes (%s).\n", message.size, o->signing);
    if (strcmp(o->signing, "deterministic") == 0)
        status = dstu9212_sign_deterministic(sig, sizeof(sig), &sig_len,
                 key.data + HEADER_BYTES, key.size - HEADER_BYTES, message.data, message.size);
    else
        status = dstu9212_sign_randomized(sig, sizeof(sig), &sig_len,
                 key.data + HEADER_BYTES, key.size - HEADER_BYTES, message.data, message.size);
    if (status != DSTU9212_OK || sig_len != dstu9212_signature_bytes()) {
        fprintf(stderr, "Signing failed.\n"); goto cleanup;
    }
    printf("[3/3] Saving a %s VSL3 container.\n", o->type);
    if (attached) {
        /* У внутрішньому підписі після повідомлення записується підпис. */
        written = write_container(output, ATTACHED, message.data, message.size, sig, sig_len);
    } else {
        written = write_container(output, DETACHED, sig, sig_len, NULL, 0);
    }
    if (!written) {
        fprintf(stderr, "Writing signature failed.\n"); goto cleanup;
    }
    if (!close_output(&output)) { fprintf(stderr, "Closing signature file failed.\n"); goto cleanup; }
    printf("Signed: %s; signature=%zu bytes.\n", o->out, sig_len);
    result = SUCCESS;
cleanup:
    if (output) fclose(output);
    if (result != SUCCESS && own_output) remove_owned(o->out);
    release_buffer(&key, 1);
    release_buffer(&message, 0);
    return result;
}

static int verify_file(const options *o)
{
    buffer key = { NULL, 0 }, input = { NULL, 0 }, signature = { NULL, 0 };
    const uint8_t *message, *sig;
    size_t message_len, sig_len = dstu9212_signature_bytes();
    int result = FAILURE, attached = strcmp(o->type, "attached") == 0;
    FILE *output = NULL;
    int own_output = 0;
    puts("[1/3] Reading files and validating VSL3 containers.");
    if (read_file(o->public_key, &key) != SUCCESS ||
        validate_container(&key, PUBLIC_KEY, dstu9212_public_key_bytes(), o->public_key) != SUCCESS ||
        read_file(o->file, &input) != SUCCESS) goto cleanup;
    if (attached) {
        if (validate_container(&input, ATTACHED, sig_len, o->file) != SUCCESS) goto cleanup;
        message = input.data + HEADER_BYTES;
        message_len = input.size - HEADER_BYTES - sig_len;
        sig = message + message_len;
    } else {
        if (read_file(o->signature, &signature) != SUCCESS ||
            validate_container(&signature, DETACHED, sig_len, o->signature) != SUCCESS) goto cleanup;
        message = input.data; message_len = input.size;
        sig = signature.data + HEADER_BYTES;
    }
    printf("[2/3] Verifying %zu original bytes with the public key.\n", message_len);
    if (dstu9212_verify_signature(key.data + HEADER_BYTES, key.size - HEADER_BYTES,
                                sig, sig_len, message, message_len) != DSTU9212_OK) {
        fprintf(stderr, "INVALID: signature does not match the file or public key.\n");
        result = INVALID_SIGNATURE; goto cleanup;
    }
    if (o->out) {
        puts("[3/3] Saving the verified original message to a new file.");
        output = create_new(o->out, 0);
        if (!output) { file_error("create", o->out); goto cleanup; }
        own_output = 1;
        if (!write_bytes(output, message, message_len) || !close_output(&output)) {
            fprintf(stderr, "Saving recovered message failed.\n"); goto cleanup;
        }
        printf("Recovered: %s (%zu bytes).\n", o->out, message_len);
    } else puts("[3/3] Verification complete.");
    puts("VALID: signature matches the file.");
    result = SUCCESS;
cleanup:
    if (output) fclose(output);
    if (result != SUCCESS && own_output) remove_owned(o->out);
    release_buffer(&key, 0); release_buffer(&input, 0); release_buffer(&signature, 0);
    return result;
}

static int run(int argc, char **argv)
{
    options o;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        help(); return SUCCESS;
    }
    if (parse_options(argc, argv, &o) != SUCCESS ||
        validate_options(&o) != SUCCESS) return FAILURE;
    if (strcmp(o.command, "generate") == 0) return generate(&o);
    if (strcmp(o.command, "sign") == 0) return sign_file(&o);
    return verify_file(&o);
}

#ifdef _WIN32
int wmain(int argc, wchar_t **wargv)
{
    char **argv = (char **)calloc((size_t)argc, sizeof(*argv));
    int i, result = FAILURE;
    SetConsoleOutputCP(CP_UTF8);
    if (!argv) { fprintf(stderr, "Memory allocation failed.\n"); return FAILURE; }
    for (i = 0; i < argc; ++i) {
        int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1, NULL, 0, NULL, NULL);
        if (!length || !(argv[i] = (char *)malloc((size_t)length))) goto cleanup;
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wargv[i], -1, argv[i], length, NULL, NULL)) goto cleanup;
    }
    result = run(argc, argv);
cleanup:
    for (i = 0; i < argc; ++i) free(argv[i]);
    free(argv);
    return result;
}
#else
int main(int argc, char **argv) { return run(argc, argv); }
#endif
