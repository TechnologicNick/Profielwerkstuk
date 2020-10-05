#pragma once

int main();
//int hash_SHA1(const char* fileName);
long long hash(unsigned char *(hash_function)(const unsigned char *d, size_t n, unsigned char *md), int bufferSize, const char* fileName);
void printResults(std::map<const char *, long long> durations, long long count);