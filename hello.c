/*
 *  hello.c: Hello application for MUL Controller 
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "hello.h"
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <topo.h>

// #define SERVER_IP "192.168.10.118"
#define CONF_FILE_PATH "/home/ctrl_connect"
#define PROXY_PORT 2345  // 数据库监听的端口
#define SLOT_LiSTEN_PORT 12000  // 本地时间片切换时，需要知道时间片切换，收消息的套接字
#define BUFSIZE 512 // 套接字缓存大小
#define ROUTE_KEY '1' // type_1
#define ROUTE_VALUE '2' // type_2

struct event *hello_timer;
struct mul_app_client_cb hello_app_cbs;

char local_ip[20] = "192.168.67.";  // 本地控制器ip
char proxy_ip[20] = "192.168.68.";  // 数据库代理ip
int slot_no = 0;    // 时间片

pthread_t pid_pkt;  // 和服务器通信的线程
int skfd_pkt = -1;  // 和服务器的通信套接字

pthread_t pid_slot; // 接收时间片切换信号的线程
int skfd_slot = -1;  // 获取时间片切换信息的套接字

tp_sw sw_list[SW_NUM];  // 卫星交换机的列表，当前时间片逻辑上的
tp_sw sw_lits_now[SW_NUM]; // 卫星交换机的列表，当前时间片探知得到的



/**
 * hello_install_dfl_flows -
 * Installs default flows on a switch
 *
 * @dpid : Switch's datapath-id
 * @return : void
 */
static void
hello_install_dfl_flows(uint64_t dpid)
{
    struct flow                 fl;
    struct flow                 mask;

    memset(&fl, 0, sizeof(fl));
    of_mask_set_dc_all(&mask);

    // /* Clear all entries for this switch */
    // mul_app_send_flow_del(HELLO_APP_NAME, NULL, dpid, &fl,
    //                       &mask, OFPP_NONE, 0, C_FL_ENT_NOCACHE, OFPG_ANY);

    // /* Zero DST MAC Drop */
    // of_mask_set_dl_dst(&mask); 
    // mul_app_send_flow_add(HELLO_APP_NAME, NULL, dpid, &fl, &mask,
    //                       HELLO_UNK_BUFFER_ID, NULL, 0, 0, 0, 
    //                       C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);  

    // /* Zero SRC MAC Drop */
    // of_mask_set_dc_all(&mask);
    // of_mask_set_dl_src(&mask); 
    // mul_app_send_flow_add(HELLO_APP_NAME, NULL, dpid, &fl, &mask, 
    //                       HELLO_UNK_BUFFER_ID, NULL, 0, 0, 0,  
    //                       C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    // /* Broadcast SRC MAC Drop */
    // memset(&fl.dl_src, 0xff, OFP_ETH_ALEN);
    // mul_app_send_flow_add(HELLO_APP_NAME, NULL, dpid, &fl, &mask,
    //                       HELLO_UNK_BUFFER_ID, NULL, 0, 0, 0,
    //                       C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Send any unknown flow to app */
    // memset(&fl, 0, sizeof(fl));
    // of_mask_set_dc_all(&mask);
    // mul_app_send_flow_add(HELLO_APP_NAME, NULL, dpid, &fl, &mask,
    //                       HELLO_UNK_BUFFER_ID, NULL, 0, 0, 0,
    //                       C_FL_PRIO_DFL, C_FL_ENT_LOCAL);
}


/**
 * hello_sw_add -
 * Switch join event notifier
 * 
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void 
hello_sw_add(mul_switch_t *sw)
{
    uint32_t sw_glabol_key;
    
    /* Add few default flows in this switch */
    hello_install_dfl_flows(sw->dpid);
    c_log_debug("switch dpid 0x%llx joined network", (unsigned long long)(sw->dpid));

}

/**
 * hello_sw_del -
 * Switch delete event notifier
 *
 * @sw : Switch arg passed by infra layer
 * @return : void
 */
static void
hello_sw_del(mul_switch_t *sw)
{
    c_log_debug("switch dpid 0x%llx left network", (unsigned long long)(sw->dpid));
}

/**
 * hello_packet_in -
 * Hello app's packet-in notifier call-back
 *
 * @sw : switch argument passed by infra layer (read-only)
 * @fl : Flow associated with the packet-in
 * @inport : in-port that this packet-in was received
 * @raw : Raw packet data pointer
 * @pkt_len : Packet length
 * 
 * @return : void
 */
static void 
hello_packet_in(mul_switch_t *sw UNUSED,
                struct flow *fl UNUSED,
                uint32_t inport UNUSED,
                uint32_t buffer_id UNUSED,
                uint8_t *raw UNUSED,
                size_t pkt_len UNUSED)
{
    c_log_info("hello app - packet-in from network");
    return;
}

/**
 * hello_core_closed -
 * mul-core connection drop notifier
 */
static void
hello_core_closed(void)
{
    c_log_info("%s: ", FN);

    /* Nothing to do */
    close(skfd_pkt);
    close(skfd_slot);
    pthread_cancel(pid_pkt);
	pthread_join(pid_pkt, NULL);
    pthread_cancel(pid_slot);
	pthread_join(pid_slot, NULL);
    return;
}

/**
 * hello_core_reconn -
 * mul-core reconnection notifier
 */
static void
hello_core_reconn(void)
{
    c_log_info("%s: ", FN);

    /* 
     * Once core connection has been re-established,
     * we need to re-register the app
     */
    mul_register_app_cb(NULL,                 /* Application specific arg */
                        HELLO_APP_NAME,       /* Application Name */
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &hello_app_cbs);      /* Event notifier call-backs */
}

/**
 * hello_port_add_cb -
 *
 * Application port add callback 
 */
static void
hello_port_add_cb(mul_switch_t *sw,  mul_port_t *port)
{
    uint32_t sw_port_tmp = 0;
    // c_log_debug("sw start %x add a port %x, MAC %s, config %x, state %x, n_stale %x", sw->dpid, port->port_no, port->hw_addr, port->config, port->state, port->n_stale);
    if(port->port_no != 0xfffe)
    {
        __tp_sw_add_port(tp_find_sw(tp_get_sw_glabol_id(sw->dpid)), port->port_no, port->hw_addr);
        sw_port_tmp = tp_get_sw_glabol_id(sw->dpid) + port->port_no;
        redis_Set_Sw2PC_Port(sw_port_tmp, 0);
    }
    // c_log_debug("sw end %x add a port %x", sw->dpid, port->port_no);
}

/**
 * hello_port_del_cb -
 *
 * Application port del callback 
 */
static void
hello_port_del_cb(mul_switch_t *sw,  mul_port_t *port)
{
    uint32_t sw_port_tmp = 0;
    // c_log_debug("sw start %x del a port %x", sw->dpid, port->port_no);
    if(port->port_no != 0xfffe)
    {
        __tp_sw_del_port(tp_find_sw(tp_get_sw_glabol_id(sw->dpid)), port->port_no);
        sw_port_tmp = tp_get_sw_glabol_id(sw->dpid) + port->port_no;
        redis_Del_Sw2PC_Port(sw_port_tmp);
    }
        
    // c_log_debug("sw end %x del a port %x", sw->dpid, port->port_no);
}

/* Network event callbacks */
struct mul_app_client_cb hello_app_cbs = {
    .switch_priv_alloc = NULL,
    .switch_priv_free = NULL,
    .switch_add_cb =  hello_sw_add,         /* Switch add notifier */
    .switch_del_cb = hello_sw_del,          /* Switch delete notifier */
    .switch_priv_port_alloc = NULL,
    .switch_priv_port_free = NULL,
    .switch_port_add_cb = hello_port_add_cb,
    .switch_port_del_cb = hello_port_del_cb,
    .switch_port_link_chg = NULL,
    .switch_port_adm_chg = NULL,
    .switch_packet_in = hello_packet_in,    /* Packet-in notifier */ 
    .core_conn_closed = hello_core_closed,  /* Core connection drop notifier */
    .core_conn_reconn = hello_core_reconn   /* Core connection join notifier */
};  

/**
 * hello_timer_event -
 * Timer running at specified interval 
 * 
 * @fd : File descriptor used internally for scheduling event
 * @event : Event type
 * @arg : Any application specific arg
 */
static void
hello_timer_event(evutil_socket_t fd UNUSED,
                  short event UNUSED,
                  void *arg UNUSED)
{
    struct timeval tv = { 1 , 0 }; /* Timer set to run every one second */

    /* Any housekeeping activity */

    evtimer_add(hello_timer, &tv);
}  

int load_conf(void)
{
    FILE * fp = NULL;
    fp = fopen(CONF_FILE_PATH, "r");

    if(fp == NULL) return 0;

    fscanf(fp, "%d", &slot_no);
    c_log_debug("slot_no:%d", slot_no);
    fscanf(fp, "%s", &local_ip[11]);
    c_log_debug("local_ip:%s", local_ip);
    fscanf(fp, "%s", &proxy_ip[11]);
    c_log_debug("proxy_ip:%s", proxy_ip);
    fclose(fp);
    return 1;
}

void* pkt_listen(void *arg)
{
    int ret = -1;
	int i, j =0;
    struct sockaddr_in addr;
    char rec[BUFSIZE] = {0};

	skfd_pkt = socket(AF_INET, SOCK_STREAM, 0);
	if ( -1 == skfd_pkt) {
		c_log_debug("socket failed");
	}

	
	// addr.sin_family = AF_INET; // 设置tcp协议族
	// addr.sin_port = htons(CLIENT_PORT); // 设置端口号
	// addr.sin_addr.s_addr = inet_addr(CLIENT_IP); // 设置ip地址

	// ret = bind(skfd_pkt, (struct sockaddr*)&addr, sizeof(addr));
	// if (ret == -1) 
    // {
    //     c_log_debug("bind failed");
	// }
 

	addr.sin_family = AF_INET; //设置tcp协议族
	addr.sin_port = htons(PROXY_PORT); //设置端口号
	addr.sin_addr.s_addr = inet_addr(proxy_ip); //设置ip地址
	
	//主动发送连接请求
	ret = connect(skfd_pkt,(struct sockaddr*)&addr, sizeof(addr));
	if(-1 == ret) 
    {
        c_log_debug("connect failed");
        return NULL;
    }

	//客户端接收来自服务端的消息
	while (1) 
    {
		bzero(&rec, sizeof(rec));
		ret = recv(skfd_pkt, &rec, sizeof(rec), 0);
        pthread_testcancel();
		if(-1 == ret) c_log_debug("recv failed");
		else if(ret > 0) 
		{
			// printf("recv from server: %s\n", rec);
			for(i = 0; rec[i] != '\0'; )
			{
				// T:1,L:2,V
                switch(rec[i])
				{
					case ROUTE_KEY:
						printf("route key = ");
						for(j = 1; j <= ((rec[i+1] - '0')*10 + (rec[i+2] - '0')); j++)
						{
							printf("%c", rec[i+2+j]);
						}
						printf("\n");
						i += (2+j);
						break;
					case ROUTE_VALUE:
						printf("route value = ");
						for(j = 1; j <= ((rec[i+1] - '0')*10 + (rec[i+2] - '0')); j++)
						{
							printf("%c", rec[i+2+j]);
						}
						printf("\n");
						i += (2+j);
						break;
					default:
						printf("received unknown packet\n");
						i++;
						break;
				}
			}
            pthread_testcancel();
		}
        // 对收到的消息进行处理
	}
}

void* slot_change_listen(void *arg)
{
    struct sockaddr_in srvaddr;
	socklen_t len = sizeof(srvaddr);
    char buf[BUFSIZE], tmp[20] = "192.168.68.";
    int ret, i;
    FILE * fp = NULL;

	bzero(&srvaddr, len);
    skfd_slot = socket(AF_INET, SOCK_DGRAM, 0);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(SLOT_LiSTEN_PORT);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// 绑定本地IP和端口
	bind(skfd_slot, &srvaddr, len);

	while(1)
	{
		bzero(buf, 30);
		recvfrom(skfd_slot, buf, BUFSIZE, 0, NULL, NULL);
        pthread_testcancel();
        // 读取配置文件
        fp = fopen(CONF_FILE_PATH, "r");
        if(fp == NULL) return 0;
        fscanf(fp, "%d", &slot_no);
        fscanf(fp, "%s", &local_ip[11]);
        fscanf(fp, "%s", &tmp[11]);
        fclose(fp);
        for(i=0; i<3; i++)
        {
            if(tmp[11+i] != proxy_ip[11+i])
            {
                close(skfd_pkt);
                pthread_cancel(pid_pkt);
                pthread_join(pid_pkt, NULL);
                for(i=0; i<3; i++)
                {
                    proxy_ip[11+i] = tmp[11+i];
                }
                ret = pthread_create(&pid_pkt, NULL, pkt_listen, NULL);
                if (ret == -1) 
                    c_log_debug("link to other db. TCP listen create failed!"); 
                else
                    c_log_debug("link to other db. TCP listen create success!");
                    break;
            }
        }
        memset(&tmp[11], 0, 3);
		// printf("%s", buf);
	}
    return NULL;
}


/**
 * hello_module_init -
 * Hello application's main entry point
 * 
 * @base_arg: Pointer to the event base used to schedule IO events
 * @return : void
 */
void
hello_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval tv = { 1, 0 };
    int ret;

    c_log_debug("%s", FN);

    if(load_conf())
        c_log_debug("Load config success！");
    else
        c_log_debug("Load config failed！");

    ret = pthread_create(&pid_pkt, NULL, pkt_listen, NULL);
    if (ret == -1) 
        c_log_debug("TCP listen failed!"); 
    else
        c_log_debug("TCP listen start!");

    ret = pthread_create(&pid_slot, NULL, slot_change_listen, NULL);
    if (ret == -1) 
        c_log_debug("Slot change thread create listen failed!"); 
    else
        c_log_debug("Slot change thread create listen success!");

    /* Fire up a timer to do any housekeeping work for this application */
    hello_timer = evtimer_new(base, hello_timer_event, NULL); 
    evtimer_add(hello_timer, &tv);

    mul_register_app_cb(NULL,                 /* Application specific arg */
                        HELLO_APP_NAME,       /* Application Name */ 
                        C_APP_ALL_SW,         /* Send any switch's notification */
                        C_APP_ALL_EVENTS,     /* Send all event notification per switch */
                        0,                    /* If any specific dpid filtering is requested */
                        NULL,                 /* List of specific dpids for filtering events */
                        &hello_app_cbs);      /* Event notifier call-backs */

    return;
}

/**
 * hello_module_vty_init -
 * Hello Application's vty entry point. If we want any private cli
 * commands. then we register them here
 *
 * @arg : Pointer to the event base(mostly left unused)
 */
void
hello_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
}

module_init(hello_module_init);
module_vty_init(hello_module_vty_init);
