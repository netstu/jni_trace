
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#include "third/utils/utils.h"
#include "third/utils/log.h"

#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

extern "C"
JNIEXPORT jboolean JNICALL init(JNIEnv *env, jclass frida_helper);

jbyteArray createByteArray(JNIEnv *env, const char *data, int len);

bool loadDex(JNIEnv *env, jbyteArray dexData, jobject classLoader);

jobject getClassLoader(JNIEnv *env, jobject obj);

jclass loadClass(JNIEnv *env, jobject classLoader, const char *clzName);

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
    }

    void postAppSpecialize(const AppSpecializeArgs *args) {
        if (process.find("com.reveny.nativecheck") == -1) {
            return;
        }
        logi("inject!");
        char **data = nullptr;
        int *len = nullptr;
        if (!ReadFile("/data/frida_helper.dex", data, len)) {
            logi("load dex error: %d", errno);
            return;
        }
        logi("will load dex");

        jclass objectClass = env->FindClass("java/lang/Object");
        auto classLoader = getClassLoader(env, objectClass);
        auto jdata = createByteArray(env, *data, *len);
        if (!loadDex(env, jdata, classLoader)) {
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
