#ifndef __MUL_GLOBAL_H__
#define __MUL_GLOBAL_H__

#include <sys/time.h>

#define SW_NUM 66
#define SLOT_TIME 40

#ifndef RETURN_RESULT
#define RETURN_RESULT
typedef enum RET_RESULT
{
    SUCCESS = 1,
    FAILURE = -1
} RET_RESULT;
#endif

#define PRO_SW2CTRL 45  // 上传到控制器的流表优先级
#define PRO_NORMAL 50   // 普通的流表优先级

#define TABLE_NORMAL 0  // 普通流表项所在table
#define TABLE_DEFAULT 1 // 默认流表项所在table

uint64_t hello_get_timeval(void)    // 获取时间戳
{
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec*1000000 + t.tv_usec;//us
}

#endif