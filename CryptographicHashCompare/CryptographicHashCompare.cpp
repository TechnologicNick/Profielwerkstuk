#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fstream>
#include <chrono>
#include <map>

#include "openssl/md4.h"
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/whrlpool.h"
#include "openssl/ripemd.h"
#include "CryptographicHashCompare.h"

int main()
{
	std::map<const char *, long long> durations;

#ifdef _DEBUG
	const char *fileName = "password_lists/test.txt";
#else
	const char *fileName = "../Debug/password_lists/rockyou.txt";
#endif // _DEBUG

	durations.insert(std::pair<const char *, long long>("MD4"      , hash(&MD4   , 16, fileName)));
	durations.insert(std::pair<const char *, long long>("MD5"      , hash(&MD5   , 16, fileName)));
	durations.insert(std::pair<const char *, long long>("SHA1"     , hash(&SHA1  , 20, fileName)));
	durations.insert(std::pair<const char *, long long>("SHA224"   , hash(&SHA224, 28, fileName)));
	durations.insert(std::pair<const char *, long long>("SHA256"   , hash(&SHA256, 32, fileName)));
	durations.insert(std::pair<const char *, long long>("SHA384"   , hash(&SHA384, 48, fileName)));
	durations.insert(std::pair<const char *, long long>("SHA512"   , hash(&SHA512, 64, fileName)));
	durations.insert(std::pair<const char *, long long>("WHIRLPOOL", hash((unsigned char *(*)(const unsigned char *d, size_t n, unsigned char *md)) &WHIRLPOOL, 64, fileName)));
	durations.insert(std::pair<const char *, long long>("RIPEMD160", hash(&RIPEMD160, 20, fileName)));

	// We don't care about speed here
	std::ifstream inFile(fileName);
	long long linecount = std::count(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(), '\n');

	printResults(durations, linecount);

	return 0;
}

long long hash(unsigned char *(hash_function)(const unsigned char *d, size_t n, unsigned char *md), int bufferSize, const char* fileName) {
#pragma warning(suppress : 4996)
	FILE* pFile = fopen(fileName, "r");
	if (pFile == NULL) perror("Error opening file");

	unsigned char obuf[64] = { 0 }; // Buffer size doesn't matter as we're only using the output for debugging

	char line[32]; // Buffer passwords get stored in

	auto start = std::chrono::high_resolution_clock::now();
	while (fgets(line, sizeof(line), pFile)) {
		hash_function((unsigned char*)line, strlen(line), obuf);
		
#ifdef _DEBUG // Printing is very slow so we're only doing that in the debug build
		printf("%s =", line);
		for (int i = 0; i < bufferSize; i++) {
			printf(" %02x", obuf[i]);
		}
		printf("\n");
#endif // DEBUG
	}
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();

	fclose(pFile);

	printf("That took %lld microseconds\n", duration);

	return duration;
}

void printResults(std::map<const char *, long long> durations, long long linecount) {
	printf("======== Hashing %lld passwords took ========\n", linecount);
	for (auto const& pair : durations) {
		double hashesPerSec = linecount / (pair.second / 1000000.0);
		printf("%s     \t%lld microseconds\t%f hashes/sec\n", pair.first, pair.second, hashesPerSec);
	}
}
