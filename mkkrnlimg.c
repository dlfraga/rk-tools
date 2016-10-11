#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
 #include <openssl/sha.h>

#include "rkcrc.h"

#define KRNL_MAGIC "KRNM"
#define SHA256ALIGN  4

struct krnl_header
{
	char magic[4];
	unsigned int length;
};

static const char *sha256dump(unsigned char *dgst, char *out)
{
	static char hex[SHA256_DIGEST_LENGTH*2];
	char *s;

	if (!out)
		out = hex;

	s = out;
	int i; for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		sprintf(s, "%02x", dgst[i]);
		s += 2;
	}

	return out;
}

int pack_krnl(FILE *fp_in, FILE *fp_out)
{
	char buf[1024];
	SHA256_CTX ctx;
	unsigned char dgst[SHA256_DIGEST_LENGTH];
	struct krnl_header header =
	{
		KRNL_MAGIC,
		0
	};

	fseek(fp_in, 0, SEEK_END);
	header.length = ftell(fp_in);
	if (header.length == 0)
		goto fail;
	fwrite(&header, sizeof(header), 1, fp_out);

	if (SHA256_Init(&ctx) != 1)
		goto fail;

	fseek(fp_in, 0, SEEK_SET);
	while (1) {
		int readlen = fread(buf, 1, sizeof(buf), fp_in);
		if (readlen == 0)
			break;

		fwrite(buf, 1, readlen, fp_out);
		if (SHA256_Update(&ctx, buf, readlen) != 1)
			goto fail;
	}

	if (SHA256_Final(dgst, &ctx) != 1)
		goto fail;

	fwrite(dgst, SHA256_DIGEST_LENGTH, 1, fp_out);

	fprintf(stderr, "SHA256: %s, LEN: %u\n", sha256dump(dgst, NULL), header.length);

	return 0;
fail:
	fprintf(stderr, "FAIL\n");
	return -1;
}

int unpack_krnl(FILE *fp_in, FILE *fp_out)
{
	char buf[1024];
	SHA256_CTX ctx;
	struct krnl_header header;
	unsigned char dgste[SHA256_DIGEST_LENGTH];
	unsigned char dgstc[SHA256_DIGEST_LENGTH];
	size_t length = 0;

	if (sizeof(header) != fread(&header, 1, sizeof(header), fp_in))
		goto fail;

	if (memcmp(header.magic, KRNL_MAGIC, sizeof(header.magic)) != 0)
		goto fail;

	fseek(fp_in, header.length + sizeof(header), SEEK_SET);
	if (SHA256_DIGEST_LENGTH != fread(dgste, 1, SHA256_DIGEST_LENGTH, fp_in))
		goto fail;

	if (SHA256_Init(&ctx) != 1)
		goto fail;

	length = header.length;
	fseek(fp_in, sizeof(header), SEEK_SET);

	while (length > 0) {
		int readlen = length < sizeof(buf) ? length : sizeof(buf);
		readlen = fread(buf, 1, readlen, fp_in);
		length -= readlen;
		fwrite(buf, 1, readlen, fp_out);
		if (readlen == 0)
			break;
		if (SHA256_Update(&ctx, buf, readlen) != 1)
			goto fail;
	}

	if (SHA256_Final(dgstc, &ctx) != 1)
		goto fail;

	if (memcmp(dgstc, dgste, SHA256_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "Failed to verify SHA256:\n");
		fprintf(stderr, "  calc: %s\n", sha256dump(dgstc, NULL));
		fprintf(stderr, "  expt: %s\n", sha256dump(dgste, NULL));
		goto fail;
	}

	fprintf(stderr, "OK\n");
	return 0;

fail:
	fprintf(stderr, "FAIL\n");
	return -1;
}

int main(int argc, char **argv)
{
	FILE *fp_in, *fp_out;
	int action = 0;

	if (argc != 4)
	{
		fprintf(stderr, "usage: %s [-a|-r] <input> <output>\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-a") == 0)
	{
		action = 1;
	} else if (strcmp(argv[1], "-r") == 0)
	{
		action = 2;
	} else {
		fprintf(stderr, "usage: %s [-a|-r] <input> <output>\n", argv[0]);
	}

	if (strcmp(argv[2], "-") == 0)
		fp_in = stdin;
	else
		fp_in = fopen(argv[2], "rb");
	if (!fp_in)
	{
		fprintf(stderr, "can't open input file '%s': %s\n", argv[2], strerror(errno));
		return 1;
	}

	if (strcmp(argv[3], "-") == 0)
		fp_out = stdout;
	else
		fp_out = fopen(argv[3], "wb");
	if (!fp_out)
	{
		fprintf(stderr, "can't open output file '%s': %s\n", argv[3], strerror(errno));
		return 1;
	}

	switch (action)
	{
	case 1:
		return pack_krnl(fp_in, fp_out);
	case 2:
		return unpack_krnl(fp_in, fp_out);
	default:
		break;
	}

	return 1;
}
