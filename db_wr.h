/***************************************************************
*   文件名称：db_wr.h
*   描    述：用于向Redis数据库进行读写操作

1、设置交换机的默认主控制器 "hset active_ctrl_%02d %u %u", slot, sw, ctrl
2、设置交换机的默认备用控制器 "hset standby_ctrl_%02d %u %u", slot, sw, ctrl
3、设置控制器的默认数据库 "hset db_%02d %u %u", slot, ctrl, db

// 维护controller当前连接的sw集合，db代理分发路由时需要查询结果，发送给相应的控制器
// 可采用set数据结构存储，https://blog.csdn.net/Xiejingfa/article/details/50594005
4、交换机连接控制器后，将该交换机添加到对应控制器的控制集合中 "sadd sw_set_%02d_%02d %u", ctrl, slot, sw
5、交换机断开连接后，将该交换机从对应控制器的控制集合中删除 "srem sw_set_%02d_%02d %u", ctrl, slot, sw

6、设置默认拓扑 "hset dfl_topo_%02d %lu %lu", slot, port, delay

7、控制器确认链路连接之后，将该链路添加到真实拓扑中  "hset real_topo_%02d %lu %lu", slot, port, delay
8、控制器确认链路断开连接之后，将该链路从真实拓扑中删除  "hdel real_topo_%02d %lu %lu", slot, port, delay
9、控制器确认链路断开连接之后，将该链路添加到失效链路列表中 "rpush fail_link_%02d %lu", slot, sw
注意：何时清空失效链路列表？下一个时间片

10、控制器下发新增流表后，把路由条目加入该链路的路由集合中 "sadd rt_set_%02d_%02d_%02d %s%s", sw1, sw2, slot, ip_src, ip_dst
11、控制器下发删除流表后，从该链路的路由集合中删去相应路由条目 "del rt_set_%02d_%02d_%02d", sw1, sw2, slot

12、设置默认路由列表 "rpush dflrt_%s%s_%02d %s", ip_src, ip_dst, slot, out_sw_port
13、设置控制器计算出的路由列表(控制器将计算好的路由写入数据库,一次完成整个条目的写入) "rpush calrt_%s%s_%02d %s", ip_src, ip_dst, slot, out_sw_port 
14、设置控制器未成功计算出的路由列表，goto table2走默认路由 "rpush failrt_%s%s_%02d 1", ip_src, ip_dst, slot

15、设置下个时间片要删除的链路列表 "rpush del_link_%02d %lu", slot, sw
    
***************************************************************/

#include "hiredis.h"
#include "topo.h"

/*宏定义*/
#define CMD_MAX_LENGHT 256
// #define REDIS_SERVER_IP "192.168.10.215"
#define REDIS_SERVER_PORT 8102

typedef enum DB_RESULT
{
    SUCCESS = 1,
    FAILURE = -1
} DB_RESULT;

/*写函数*/
// DB_RESULT Set_Ctrl_Id(uint32_t ip, uint16_t id);                         /*设置控制器信息 IP->ID*/
// DB_RESULT Set_Link_Delay(uint32_t port1, uint32_t port2, uint64_t delay);   /*设置链路信息 (node1,node2)->时延*/
// DB_RESULT Clr_Link_Delay(uint32_t port1, uint32_t port2);                   /*清除链路信息*/
// DB_RESULT Set_Pc_Sw_Port(uint32_t ip, uint32_t port);                       /*设置PC信息 IP->连接的交换机端口*/
// DB_RESULT Set_Sw_Delay(uint16_t cid, uint8_t sid, uint64_t delay);          /*设置交换机信息 (CID,SID)->到控制器的时延*/
// DB_RESULT Clr_Sw_Delay(uint16_t cid, uint8_t sid);                          /*清除交换机信息*/
// DB_RESULT Set_Route(uint32_t ip_src, uint32_t ip_dst, uint32_t out_sw_port);/*设置路由信息 添加到列表头部*/
// DB_RESULT Clr_Route(uint32_t ip_src, uint32_t ip_dst);                      /*清除路由信息*/

// write switch <-> controller(active and standby)
DB_RESULT Set_Active_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char *redis_ip);
DB_RESULT Set_Standby_Ctrl(uint32_t sw, uint32_t ctrl, int slot, char *redis_ip);
// write controller <-> switches set
DB_RESULT Add_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char *redis_ip);
DB_RESULT Del_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char *redis_ip);
// write controller <-> database
DB_RESULT Set_Ctrl_Conn_Db(uint32_t ctrl, uint32_t db, int slot, char *redis_ip);
// write default topo
DB_RESULT Set_Topo(uint32_t port1, uint32_t port2, uint64_t delay, int slot, char *redis_ip);
// write real topo that links must be connected
DB_RESULT Add_Real_Topo(uint32_t port1, uint32_t port2, int slot, char *redis_ip);
DB_RESULT Del_Real_Topo(uint32_t port1, uint32_t port2, int slot, char *redis_ip);
// write default routes(s2s/d2d/c2s/c2d)
DB_RESULT Set_Dfl_Route(char *ip_src, char *ip_dst, char *out_sw_port, int slot, char *redis_ip);
DB_RESULT Set_Cal_Route(char *ip_src, char *ip_dst, char *out_sw_port, int slot, char *redis_ip);
DB_RESULT Set_Cal_Fail_Route(char *ip_src, char *ip_dst, int slot, char *redis_ip);
// write links that next slot will be deleted
DB_RESULT Set_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char *redis_ip);
// write links that have been disconnected
//注意：何时清空失效链路列表？下一个时间片
DB_RESULT Set_Fail_Link(uint32_t sw1, uint32_t sw2, int slot, char *redis_ip); 
// write link <-> routes set
DB_RESULT Add_Rt_Set(uint32_t sw1, uint32_t sw2, char *ip_src, char *ip_dst, int slot, char *redis_ip);
DB_RESULT Del_Rt_Set(uint32_t sw1, uint32_t sw2, int slot, char *redis_ip);


/*读函数*/
// uint16_t Get_Ctrl_Id(uint32_t ip);                       /*获取控制器ID*/
// uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2); /*获取链路时延*/
// uint32_t Get_Pc_Sw_Port(uint32_t ip);                    /*获取PC连接的交换机端口*/
// uint64_t Get_Sw_Delay(uint16_t cid, uint8_t sid);        /*获取交换机到控制器的时延*/

// read switch <-> controller(active and standby)
uint32_t Get_Active_Ctrl(uint32_t sw, int slot, char *redis_ip);
uint32_t Get_Standby_Ctrl(uint32_t sw, int slot, char *redis_ip);
// lookup controller <-> switches set
DB_RESULT Lookup_Sw_Set(uint32_t ctrl, uint32_t sw, int slot, char *redis_ip);
// read controller <-> database
uint32_t Get_Ctrl_Conn_Db(uint32_t ctrl, int slot, char *redis_ip);
//read default topo from redis to sw_list
DB_RESULT Get_Topo(int slot, char *redis_ip, tp_sw sw_list[SW_NUM]);
//read real topo from redis to sw_list
DB_RESULT Get_Real_Topo(int slot, char *redis_ip, tp_sw sw_list[SW_NUM]);
// lookup whether link will be deleted in next slot
DB_RESULT Lookup_Del_Link(uint32_t sw1, uint32_t sw2, int slot, char *redis_ip);
// read link delay
uint64_t Get_Link_Delay(uint32_t port1, uint32_t port2, int slot, char *redis_ip);

/*执行命令*/
DB_RESULT redis_connect(redisContext **context, char *redis_ip);
DB_RESULT exeRedisIntCmd(char *cmd, char *redis_ip); // 写操作返回int
