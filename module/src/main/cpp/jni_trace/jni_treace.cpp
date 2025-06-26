#include <jni.h>
#include <vector>
#include <string>
#include <regex>
#include <set>
#include <dlfcn.h>

#include "../third/byopen/hack_dlopen.h"
#include "../third/utils/jni_helper.hpp"
#include "../third/utils/linux_helper.h"
#include "../third/utils/utils.h"
#include "../third/utils/log.h"
#include "../base/when_hook.h"
#include "../base/hook.h"

#include "parse_java_sig.h"
#include "jni_helper.h"
#include "jni_treace.h"
#include "format.h"
#include "art_method_name.h"

using namespace std;

jobject CallStaticObjectMethod(JNIEnv *env, void *soc, jclass, jmethodID mid, ...);

JniTrace jniTrace;
JniHelper jniHelper;
__thread bool passJniTrace = false;
__thread bool passCallMethod = false;
namespace format {
    DECLARE_Java_Format_Func(in_java_parse) {
//        logd("parse in java: %s %p ", args_type.c_str(), obj.l);
        if (obj.l == nullptr) {
            return "null";
        }
//#ifndef Android12
//    if (!jniTrace.jniHelper.HandleScopeContains(env->env, obj.l)) {
//        return xbyl::format_string("invalid object[%s: %p]", args_type.c_str(), obj.l);
//    }
//    if (env->env->IsSameObject(obj.l, nullptr)) {
//        return xbyl::format_string("deleted object[%s: %p]", args_type.c_str(), obj.l);
//    }
//#endif
        jobject gref = obj.l;
        passCallMethod = true;
        auto jret = env->CallStaticObjectMethod(jniTrace.frida_helper, jniTrace.object_2_string,
                                                gref);
//    auto jret = (jstring) CallStaticObjectMethod(env->env, env->soc, jniTrace.frida_helper,
//                                                 jniTrace.object_2_string, gref);
        passCallMethod = false;
        if (jret == nullptr) {
            return "null";
        }
        const char *ret = env->GetStringUTFChars((jstring) jret, nullptr);
        string result = ret;
        delete[] ret;
        return result;
    }
}

static int CheckAllowModule(const vector<Stack> &frame, const initializer_list<string> &strs) {
    for (const auto &item: frame) {
        for (int i = 0; i < strs.size(); i++) {
            if (item.name.find(*(strs.begin() + i)) != string::npos) {
                return i;
            }
        }
    }

    string logs = "pass: ";
    for (const auto &item: frame) {
        logs += item.name + ", ";
    }
    logi(logs.c_str());
    return -1;
}

static int CheckFirstModule(const vector<Stack> &frame, const initializer_list<string> &strs) {
    for (int i = 0; i < strs.size(); i++) {
        if (frame[0].name.find(*(strs.begin() + i)) != string::npos) {
            return i;
        }
    }

    string logs = "pass: ";
    for (const auto &item: frame) {
        logs += item.name + ", ";
    }
    logi(logs.c_str());
    return -1;
}

extern "C"
JNIEXPORT jboolean JNICALL init(JNIEnv *env, jclass frida_helper) {
    if (!jniTrace.init) {
        vector<string> passJavaMethod = {
                "void android.view.Choreographer.postFrameCallback(android.view.Choreographer$FrameCallback)",
                "void android.view.Choreographer.removeFrameCallback(android.view.Choreographer$FrameCallback)",
                "boolean android.os.Handler.postDelayed(java.lang.Runnable, long)",
                "long java.lang.Long.longValue()",
                "long java.lang.System.nanoTime()"
        };

        logi("init jni trace!");

        fake_dlctx_ref_t handleLibArt = hack_dlopen("libart.so", 0);
        defer([&]() {
            hack_dlclose(handleLibArt);
        });
        if (!handleLibArt) {
            loge("open handleLibArt error!");
            return false;
        }
        if (!jniHelper.Init(handleLibArt)) {
            loge("jniHelper Init error!");
            return false;
        }
        jniTrace.Init((jclass) env->NewGlobalRef(frida_helper), handleLibArt,
                      [](const vector<Stack> &frame) -> int {
                          return CheckFirstModule(frame, {
                                  {"libandroid_runtime.so"},
                                  {"libanalyse.so"},
                                  {"libart.so"},
                                  {"libjavacore.so"},
                                  {"libnativeloader.so"},
                                  {"libopenjdk.so"},
                                  {"libopenjdkjvm.so"},
                                  {"libjavacrypto.so"},
                                  {"libicu_jni.so"},
                                  {"libgui.so"},
                                  {"libhwui.so"},
                                  {"boot.oat"},
                                  {"libnms.so"},
                                  {"liballiance.so"},
                                  {"libmonochrome_64.so"},
                                  {"libframework-connectivity-tiramisu-jni.so"},
                                  {"pcam.jar"},
                                  {"libapminsighta.so"},
                                  {"libmedia_jni.so"},
                                  {"com.google.android.gms"},
                                  {"com.google.android.trichrome"},
                                  {"libwebviewchromium_loader.so"},
                                  {"libconscrypt_gmscore_jni.so"},
                                  {"libzygisk.so"},
                          }) == -1 ? 1 : -1;
                      },
                      passJavaMethod);
        jniTrace.Hook();
    }
    return true;
}