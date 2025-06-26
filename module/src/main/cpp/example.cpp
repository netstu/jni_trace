
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <android/log.h>

#include "third/utils/utils.h"
#include "third/utils/log.h"
#include "third/byopen/hack_dlopen.h"
#include "third/dobby/include/dobby.h"
#include "third/utils/linux_helper.h"
#include "global/global.h"
#include "base/when_hook.h"
#include "dump_so.h"
#include "zygisk.hpp"

using namespace std;
using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

extern "C"
JNIEXPORT jboolean JNICALL init(JNIEnv *env, jclass frida_helper);

jbyteArray createByteArray(JNIEnv *env, const char *data, int len);

bool loadDex(JNIEnv *env, jbyteArray dexData, jobject classLoader);

jobject getClassLoader(JNIEnv *env, jobject obj);

jclass loadClass(JNIEnv *env, jobject classLoader, const char *clzName);

jobject loadDexFromMemory(JNIEnv *env, char *dexData, int dexLen);

uint64_t (*pcheck_fun2)(uint64_t some_obj);

uint64_t (*pcheck_fun3)(uint64_t some_obj);

uint64_t check_fun2(uint64_t some_obj) {
    auto r = pcheck_fun2(some_obj);
    logi("check fun2 %d", r);
    return 0;
}

uint64_t check_fun3(uint64_t some_obj) {
    auto r = pcheck_fun3(some_obj);
    logi("check fun3 %d", r);
    return 0;
}

uint64_t baseAddr;
#define  FastStack0()  ((uint64_t)__builtin_return_address(0)-baseAddr)
#define  FastStack1()  ((uint64_t)__builtin_return_address(1)-baseAddr)

void (*plog_msg)(uint64_t *a1, int a2, uint64_t a3, uint64_t a4, const char *fmt, ...);

void log_msg(uint64_t *a1, int a2, uint64_t a3, uint64_t a4, const char *fmt, ...) {
    va_list args;
    va_list cargs;
    va_start(args, fmt);
    va_copy(cargs, args);
    string logs = xbyl::format_string(fmt, cargs);
    if (logs.find("Terminating application due to detection") != -1) {
        logi("log msg: %s %p,%p", logs.c_str(), FastStack0(), FastStack1());
    } else {
        logi("log msg: %s %p", logs.c_str(), FastStack0());
    }
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        this->process = process;
        env->ReleaseStringUTFChars(args->nice_name, process);
        setPkgName(process);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) {
        if (process.find("com.reveny.nativecheck") == -1 &&
            process.find("com.org.tuokuan") == -1) {
            return;
        }
        logi("inject!");
        dump_so_delay("libshield.so", 15);
        dump_so_delay("libreveny.so", 0);
        (new thread([=]() {
            MapsHelper maps;
            if (maps.refresh("memfd:") == 0) {
                LOGI("dump_so open maps error!");
                return;
            }
            for (auto item: maps.mapsInfo) {
                if (item.path.find("/memfd:") != string::npos &&
                    item.path.find("jit-zygote-cache") == string::npos &&
                    item.path.find("jit-cache") == string::npos) {
                    logi("find mem so: %s", item.path.c_str());
                    dump_so(item.path.substr(item.path.find(":") + 1).substr(0, 8),
                            "/data/data/" + getPkgName());
                }
            }
        }))->detach();

        WhenSoInitHook("libshield.so",
                       [](const string &path, void *addr, const string &funcType) {
                           logi("on shield load");
                           void *unused;
                           module_info_t info;
                           hack_get_module_info("libshield.so", &info);
                           baseAddr = (uint64_t) info.module_address;

                           DobbyHook((void *) (baseAddr + 0x0528CB0),
                                     (dobby_dummy_func_t) log_msg,
                                     (dobby_dummy_func_t *) &plog_msg);

                           DobbyHook((void *) (baseAddr + 0x040E77C),
                                     (dobby_dummy_func_t) check_fun2,
                                     (dobby_dummy_func_t *) &pcheck_fun2);

                           DobbyHook((void *) (baseAddr + 0x426138),
                                     (dobby_dummy_func_t) check_fun3,
                                     (dobby_dummy_func_t *) &pcheck_fun3);
                       });

        char *data = nullptr;
        int len;
        if (!ReadFile("/data/frida_helper.dex", &data, &len)) {
            logi("load dex error: %d", errno);
            return;
        }
        logi("will load dex");
        auto classLoader = loadDexFromMemory(env, data, len);
        if (classLoader == nullptr) {
            logi("load dex error!");
            return;
        }
        jclass frida_helper = loadClass(env, classLoader, "com.frida.frida_helper");
        if (frida_helper == nullptr) {
            logi("frida_helper is null!");
            return;
        }
        logi("will init jni trace");
        init(env, frida_helper);
        logi("finish");
    }

private:
    Api *api;
    JNIEnv *env;
    string process;
};

static void companion_handler(int i) {
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)

REGISTER_ZYGISK_COMPANION(companion_handler)
