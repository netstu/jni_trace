#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "../utils/jni_helper.hpp"
#include "../utils/log.h"

using namespace std;

void log2file(const string &log);

void log2file(const char *fmt, ...);

class app_file_writer {
public:
    app_file_writer(const string &dataPath, const string &name) {
        open(dataPath, name);
    }

    app_file_writer() = default;

    ~app_file_writer() {
        if (file == nullptr) {
            return;
        }
        fclose(file);
    }

    bool is_open() {
        return file != nullptr;
    }

    bool open(const string &dataPath, const string &name) {
        lock_guard<mutex> guard(fileLock);
        if (is_open()) {
            return true;
        }
        this->appDataPath = dataPath;
        this->fileName = name;
        this->myPid = getpid();
        file = open_file(dataPath, name);
        return file != nullptr;
    }

    void write2file(const char *data, int len) {
        lock_guard<mutex> guard(fileLock);
        check_process();
        if (len > 0 && file != nullptr) {
            fwrite(data, 1, len, file);
            fflush(file);
        }
    }

    void write2file(const string &data) {
        lock_guard<mutex> guard(fileLock);
        check_process();
        if (data.size() > 0 && file != nullptr) {
            fwrite(data.c_str(), 1, data.size(), file);
            fwrite("\n", 1, 1, file);
            fflush(file);
        }
    }

private:
    int myPid{};
    string appDataPath;
    string fileName;
    FILE *file{};
    mutex fileLock;

    void check_process() {
        if (myPid == getpid()) {
            return;
        }
        LOGI("log pid change: %d -> %d", myPid, getpid());
        myPid = getpid();
        file = open_file(this->appDataPath, this->fileName);
    }

public:
    static FILE *open_file(const string &appDataPath, const string &name) {
        srandom(::time(nullptr) + getpid());
        char path[256];
        snprintf(path, sizeof(path), "%s/%s_%d_%ld", appDataPath.c_str(), name.c_str(), getpid(), random());
        FILE *file = fopen(path, "wb");
        if (!file) {
            LOGI("analyse open log file %s error: %d", path, errno);
            return nullptr;
        }
        return file;
    }
};