直接编译, 模块生成在out目录
需要删除postAppSpecialize(const AppSpecializeArgs *args)中我调试其他app的代码
需要在jni_trace.cpp 
JNIEXPORT jboolean JNICALL init(JNIEnv *env, jclass frida_helper)函数中配置你目标so 

疯狂星期四 v我50 
我是秦始皇 v我50封你为大牛马

