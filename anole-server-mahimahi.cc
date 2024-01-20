
#include <cstdlib>
#include <sys/select.h>
#include "define.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <string>
#include <cstdio>
#include <errno.h>

#define ENABLE_ANOLE_RL false

// #define CHANGE_TARGET 1
#define MAX_CWND 10000
#define MIN_CWND 4
/******************************************************************************************/
#include <queue>
#include <cmath>
#include <algorithm>
#include <random>
typedef unsigned int __u32;
/************************************参数 & 全局变量定义************************************/
/**********效用模块**********/
#define EXPONENT_T 0.9
#define ALPHA 10
#define BETA 1
#define LAMBDA 11.35 // 四者选值都是根据vivace的
#define MU 0.1
// std::queue<double> rtt_queue;
// double rtt_min = 20; //  注意我这里自己设的是rtt_min
/**********最优cwnd模块**********/
#define CWND_THRESHOLD 2
/**********置信度模块**********/
#define THETA 0.05
#define ETA_ON 0.8
#define ETA_OFF 0.6
#define DELTA_ETA 0.01
double eta_cl = 1;
double eta_rl = 1;
/*************逻辑************/
double epsilon = 0.8;
#define TCP_CWND 38
#define TCP_CWND_USER 39
#define TCP_RTT                 40
#define TCP_RTTS                41
#define TCP_RTTMIN              42
int CUR_CWND;
int cur_prev_cwnd = 100;
int cur_cl_cwnd = 100;
int cur_rl_cwnd = 100;
bool is_right_prev;
bool is_right_cl;
bool is_right_rl;
int cur_rtt;
bool set_if_out = false;
// int sock_fd;
struct tcp_info info_cur, info, info_pre;
socklen_t info_length;
double ucl, url, uprev;
int a_cwnd, b_cwnd, c_cwnd, optimal_cwnd;
double ua, ub, uc, u_optimal;
__u32 ONE_WAY_DELAY = 25;
/******************************************实现*********************************************/
/******************************************效用函数模块**************************************/
void print_rtt(int tt)
{
    __u32 his_rtt[50];
	__u32 length = 200;
    if (getsockopt(sock_for_cnt[tt], IPPROTO_TCP, TCP_RTTS, &his_rtt[0], &length) < 0){
        printf("ERROR: set TCP_RTTS option %s\n", strerror(errno));
    }
    for(int i=0; i < 5; i++) {
        DBGMARK(5, 1, "\nhistory_rtt = %u %u %u %u %u %u %u %u %u %u\n", 
        his_rtt[49-i*10], his_rtt[48-i*10], his_rtt[47-i*10], his_rtt[46-i*10], his_rtt[45-i*10],
        his_rtt[44-i*10], his_rtt[43-i*10], his_rtt[42-i*10], his_rtt[41-i*10], his_rtt[40-i*10]);
    }
    return;
}
double delta_rtt(int tt)
{ // 计算 delta_rtt
    // if (rtt_queue.size() < 10)
    //     return 0;
    // std::queue<double> temp_queue = rtt_queue;
    __u32 his_rtt[20];
	__u32 length = 80;
    if (getsockopt(sock_for_cnt[tt], IPPROTO_TCP, TCP_RTTS, &his_rtt[0], &length) < 0){
        printf("ERROR: set TCP_RTTS option %s\n", strerror(errno));
        return 1;
    }
    // DBGMARK(5, 1, "\nhistory_rtt = %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
    // his_rtt[19], his_rtt[18], his_rtt[17], his_rtt[16], his_rtt[15], 
    // his_rtt[14], his_rtt[13], his_rtt[12], his_rtt[11], his_rtt[10], 
    // his_rtt[9], his_rtt[8], his_rtt[7], his_rtt[6], his_rtt[5], 
    // his_rtt[4], his_rtt[3], his_rtt[2], his_rtt[1], his_rtt[0]);
    /********************************************************************/
    double result = 0;
    for (int i = 0; i < 20; i++)
    {
        // if (i & 1)
        //     result += his_rtt[i];
        // else
        //     result -= his_rtt[i];
        if(i >= 10) result += his_rtt[i];
        else result -= his_rtt[i];
    }
    /********************************************************************/
    __u32 min_rtt = 0;
    length = 4;
    if (getsockopt(sock_for_cnt[tt], IPPROTO_TCP, TCP_RTTMIN, &min_rtt, &length) < 0){
        printf("ERROR: set TCP_RTTMIN option %s\n", strerror(errno));
        return 1;
    }
    // return (result - min_rtt) / min_rtt;
    DBGMARK(5, 1, "\nresult = %.8lf \n", result);
    double res = result / min_rtt / 10;
    DBGMARK(5, 1, "\ndrtt = %.8lf \n", res);
    double sum = 0;
    for(int i=10; i < 20; i++) sum += his_rtt[i];
    sum /= 10;
    res += pow(400, 1.0 * (sum - min_rtt) / min_rtt) - 1;
    DBGMARK(5, 1, "\ndrtt = %.8lf \n", res);
    return res;
}
int get_cur_cwnd(int i)
{
    info_length = sizeof(info_cur);
    if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info_cur, &info_length))
    {
        DBGMARK(5, 1, "getsockopt1\n");
        perror("getsockopt");
    }

    return info_cur.tcpi_snd_cwnd;
}
__u32 read_cur_rtt(int tt){
    __u32 res = 0;
    __u32 length = 4;
    if (getsockopt(sock_for_cnt[tt], IPPROTO_TCP, TCP_RTT, &res, &length) < 0){
        printf("ERROR: set TCP_RTT option %s\n", strerror(errno));
        return 1;
    }
    return res;
}
__u32 read_min_rtt(int tt){
    __u32 res = 0;
    __u32 length = 4;
    if (getsockopt(sock_for_cnt[tt], IPPROTO_TCP, TCP_RTTMIN, &res, &length) < 0){
        printf("ERROR: set TCP_RTTMIN option %s\n", strerror(errno));
        return 1;
    }
    return res;
}
double utility_value_module(int func_cwnd, bool *flag, int i)
{
    // info_length = sizeof(info_cur);
    // if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info_cur, &info_length))
    // {
    //     perror("getsockopt");
    // }
    // cur_rtt = info_cur.tcpi_rtt;
    cur_rtt = read_cur_rtt(i);
    double rate = 1500.0 * 8 * func_cwnd / cur_rtt;
    DBGMARK(5, 1, "\nin_funcion rate = %.2lf \n", rate);
    // 第一部分 - 第二部分
    double drtt = delta_rtt(i);
    if (drtt > 0.6)
        *flag = true;
    else
        *flag = false;
    // DBGMARK(5, 1, "\ndrtt = %.8lf \n", drtt);
    double u_value = ALPHA * pow(rate, EXPONENT_T) - BETA * rate * max(0.0, drtt);
    
    // 先读取min_rtt
    __u32 min_rtt = 0, length = 4;
    if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_RTTMIN, &min_rtt, &length) < 0){
        printf("ERROR: set TCP_RTTMIN option %s\n", strerror(errno));
        return 1;
    }
    // 第三部分
    // double cur_rtt = info_cur.tcpi_rtt;
    __u32 minrtt = read_min_rtt(i);
    __u32 currtt = read_cur_rtt(i);
    if(double(1.0 * currtt / minrtt) > 1 + MU) u_value -= LAMBDA * rate * currtt / minrtt;
    return u_value;
}
/****************************************最优cwnd模块************************************/
void set_cwnd(int cwnd_to_set, int i)
{
    uint64_t cwnd = uint64_t(cwnd_to_set);

    if (cwnd > 600 || cwnd <= 2)
    {
        return;
    }
    DBGMARK(5, 1, "Cwnd is normal, setting cwnd = %d\n", cwnd_to_set);
    if (setsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_CWND_USER, &cwnd_to_set, sizeof(cwnd_to_set)) < 0)
    {
        DBGMARK(5, 1, "ERROR: set TCP_CWND_USER option %s\n", strerror(errno));
    }
    // if (setsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_CWND, &cwnd_to_set, sizeof(cwnd_to_set)) < 0)
    // {
    //     DBGMARK(5, 1, "ERROR: set TCP_CWND option %s\n", strerror(errno));
    // }
    set_if_out = false;
}

void change_to_abc()
{
    if (cur_cl_cwnd <= cur_rl_cwnd && cur_rl_cwnd <= cur_prev_cwnd)
    {
        a_cwnd = cur_cl_cwnd, b_cwnd = cur_rl_cwnd, c_cwnd = cur_prev_cwnd;
        ua = ucl, ub = url, uc = uprev;
    }
    else if (cur_cl_cwnd <= cur_prev_cwnd && cur_prev_cwnd <= cur_rl_cwnd)
    {
        a_cwnd = cur_cl_cwnd, b_cwnd = cur_prev_cwnd, c_cwnd = cur_rl_cwnd;
        ua = ucl, ub = uprev, uc = url;
    }
    else if (cur_rl_cwnd <= cur_cl_cwnd && cur_cl_cwnd <= cur_prev_cwnd)
    {
        a_cwnd = cur_rl_cwnd, b_cwnd = cur_cl_cwnd, c_cwnd = cur_prev_cwnd;
        ua = url, ub = ucl, uc = uprev;
    }
    else if (cur_rl_cwnd <= cur_prev_cwnd && cur_prev_cwnd <= cur_cl_cwnd)
    {
        a_cwnd = cur_rl_cwnd, b_cwnd = cur_prev_cwnd, c_cwnd = cur_cl_cwnd;
        ua = url, ub = uprev, uc = ucl;
    }
    else if (cur_prev_cwnd <= cur_cl_cwnd && cur_cl_cwnd <= cur_rl_cwnd)
    {
        a_cwnd = cur_prev_cwnd, b_cwnd = cur_cl_cwnd, c_cwnd = cur_rl_cwnd;
        ua = uprev, ub = ucl, uc = url;
    }
    else if (cur_prev_cwnd <= cur_rl_cwnd && cur_rl_cwnd <= cur_cl_cwnd)
    {
        a_cwnd = cur_prev_cwnd, b_cwnd = cur_rl_cwnd, c_cwnd = cur_cl_cwnd;
        ua = uprev, ub = url, uc = ucl;
    }
    DBGMARK(5, 1, "\na = %u, b = %u, c = %u \n", a_cwnd, b_cwnd, c_cwnd);
}
void equation8()
{
    return;
}
void cmp_threshold()
{ // a和b的cwnd小于threshold
    if (ua > ub)
        optimal_cwnd = a_cwnd, u_optimal = ua;
    else
        optimal_cwnd = b_cwnd, u_optimal = ub;
    return;
}
void cal_optimal_cwnd(int situation)
{
    if (situation == 1)
    {
        // equation8();
        optimal_cwnd = (a_cwnd + b_cwnd) / 2, u_optimal = max(ua, ub);
    }
    else if (situation == 2)
    {
        if (b_cwnd - a_cwnd <= CWND_THRESHOLD)
            cmp_threshold();
        else
            // equation8();
            optimal_cwnd = (a_cwnd + b_cwnd) / 2, u_optimal = max(ua, ub);
    }
    else if (situation == 3)
    {
        if (b_cwnd - a_cwnd <= CWND_THRESHOLD)
            cmp_threshold();
        else // 这里根据历史记录的C推断R暂时没写进去
            optimal_cwnd = (a_cwnd + b_cwnd) / 2, u_optimal = max(ua, ub);
        // optimal_cwnd = b_cwnd, u_optimal = ub;
    }
    else if (situation == 4)
    {
        optimal_cwnd = c_cwnd, u_optimal = uc;
    }
    DBGMARK(5, 1, "\n当前属于情况 = %u\n", situation);
    DBGMARK(5, 1, "\n最优的optimal cwnd = %u, 最优的效用值u_optimal = %.2lf\n", optimal_cwnd, u_optimal);
    return;
}
/******************************************置信度模块***************************************/
void confidence_value_module(double u, double umax, double *eta)
{
    double y = u / umax + THETA;
    *eta = min(1.0, max(0.50, *eta * y));
    return;
}
/******************************************************************************************
 * main函数
 */

int main(int argc, char **argv)
{
    // init_queue();
    DBGPRINT(DBGSERVER, 4, "Main\n");
    if (argc != 8)
    {
        DBGERROR("argc:%d\n", argc);
        for (int i = 0; i < argc; i++)
            DBGERROR("argv[%d]:%s\n", i, argv[i]);
        usage();
        return 0;
    }
    srand(raw_timestamp());

    signal(SIGSEGV, handler); // install our handler
    signal(SIGTERM, handler); // install our handler
    signal(SIGABRT, handler); // install our handler
    signal(SIGFPE, handler);  // install our handler
    signal(SIGKILL, handler); // install our handler

    // client作为发送端等待
    int flow_num; // 流数量
    flow_num = FLOW_NUM;
    client_port = atoi(argv[1]); // client端口
    path = argv[2];              // rl-module的path
    target = 50;                 // 目标RTT
    target_ratio = 1;
    report_period = atoi(argv[3]);
    scheme = argv[4]; // 内核算法
    actor_id = atoi(argv[5]);
    duration = atoi(argv[6]);
    duration_steps = atoi(argv[7]);

    //********************************************************************
    std::ofstream file1("1.txt", std::ios::app);
    file1 << "start_server开始" << std::endl; // 写入信息

    start_server(flow_num, client_port);
    DBGMARK(DBGSERVER, 5, "DONE!\n");
    //********************************************************************
    file1 << "start_server结束" << std::endl; // 写入信息
    file1.close();
    //********************************************************************
    shmdt(shared_memory);
    shmctl(shmid, IPC_RMID, NULL);
    shmdt(shared_memory_rl);
    shmctl(shmid_rl, IPC_RMID, NULL);
    return 0;
}

void usage()
{
    DBGMARK(0, 0, "./server [port] [path to ddpg.py] [Report Period: 20 msec] [First Time: 1=yes(learn), 0=no(continue learning), 2=evaluate] [actor id=0, 1, ...]\n");
}

void start_server(int flow_num, int client_port)
{
    cFlow *flows;
    int num_lines = 0;
    sInfo *info;
    info = new sInfo;
    flows = new cFlow[flow_num];

    // 检查flow是否为空
    if (flows == NULL)
    {
        DBGMARK(0, 0, "flow generation failed\n");
        return;
    }

    // threads
    pthread_t data_thread;
    pthread_t cnt_thread;
    pthread_t timer_thread;

    // Server address
    struct sockaddr_in server_addr[FLOW_NUM];
    // Client address
    struct sockaddr_in client_addr[FLOW_NUM];
    // Controller address
    // struct sockaddr_in ctr_addr;

    for (int i = 0; i < FLOW_NUM; i++)
    {
        memset(&server_addr[i], 0, sizeof(server_addr[i]));
        // IP protocol
        server_addr[i].sin_family = AF_INET;
        // Listen on "0.0.0.0" (Any IP address of this host)
        server_addr[i].sin_addr.s_addr = INADDR_ANY;
        // Specify port number
        server_addr[i].sin_port = htons(client_port + i);

        // Init socket
        if ((sock[i] = socket(PF_INET, SOCK_STREAM, 0)) < 0)
        {
            DBGMARK(0, 0, "sockopt: %s\n", strerror(errno));
            return;
        }

        int reuse = 1;
        if (setsockopt(sock[i], SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0)
        {
            perror("setsockopt(SO_REUSEADDR) failed");
        }

        // Bind socket on IP:Port
        if (bind(sock[i], (struct sockaddr *)&server_addr[i], sizeof(struct sockaddr)) < 0)
        {
            DBGMARK(0, 0, "bind error srv_ctr_ip: 000000: %s\n", strerror(errno));
            close(sock[i]);
            return;
        }

        if (scheme)
        {
            if (setsockopt(sock[i], IPPROTO_TCP, TCP_CONGESTION, scheme, strlen(scheme)) < 0)
            {
                DBGMARK(0, 0, "TCP congestion doesn't exist: %s\n", strerror(errno));
                return;
            }
        }
    }

    char cmd[1000];

    info->trace = trace;
    info->num_lines = num_lines;
    /**
     *Setup Shared Memory
     */
    key = (key_t)(actor_id * 10000 + rand() % 10000 + 1);
    key_rl = (key_t)(actor_id * 10000 + rand() % 10000 + 1);
    // Setup shared memory, 11 is the size
    if ((shmid = shmget(key, shmem_size, IPC_CREAT | 0666)) < 0)
    {
        printf("Error getting shared memory id");
        return;
    }

    // Attached shared memory
    if ((shared_memory = (char *)shmat(shmid, NULL, 0)) == (char *)-1)
    {
        printf("Error attaching shared memory id");
        return;
    }

    // Setup shared memory, 11 is the size
    if ((shmid_rl = shmget(key_rl, shmem_size, IPC_CREAT | 0666)) < 0)
    {
        printf("Error getting shared memory id");
        return;
    }

    // Attached shared memory
    if ((shared_memory_rl = (char *)shmat(shmid_rl, NULL, 0)) == (char *)-1)
    {
        printf("Error attaching shared memory id");
        return;
    }

    sprintf(cmd, "/usr/bin/python %s/d5.py --load --tb_interval=1 --base_path=%s --task=%d --job_name=actor --mem_r=%d --mem_w=%d&", path, path, actor_id, (int)key, (int)key_rl);
    DBGPRINT(0, 0, "Starting RL Module (With load) ...\n%s", cmd);

    initial_timestamp();
    system(cmd);

    // Wait to get OK signal (alpha=OK_SIGNAL)
    bool got_ready_signal_from_rl = false;
    int signal;
    char *num;
    char *alpha;
    char *save_ptr;
    int signal_check_counter = 0;
    while (!got_ready_signal_from_rl)
    {
        // Get alpha from RL-Module
        signal_check_counter++;
        num = strtok_r(shared_memory_rl, " ", &save_ptr);
        alpha = strtok_r(NULL, " ", &save_ptr);
        if (num != NULL && alpha != NULL)
        {
            signal = atoi(alpha);
            if (signal == OK_SIGNAL)
            {
                got_ready_signal_from_rl = true;
            }
            else
            {
                usleep(1000);
            }
        }
        else
        {
            usleep(10000);
        }
        if (signal_check_counter > 18000)
        {
            DBGERROR("After 3 minutes, no response (OK_Signal) from the Actor %d is received! We are going down down down ...\n", actor_id);
            return;
        }
    }
    DBGPRINT(0, 0, "RL Module is Ready. Let's Start ...\n\n");
    usleep(actor_id * 10000 + 10000);

    // Start listen
    int maxfdp = -1;
    fd_set rset;
    FD_ZERO(&rset);
    // The maximum number of concurrent connections is 1
    for (int i = 0; i < FLOW_NUM; i++)
    {
        listen(sock[i], 1);
        // To be used in select() function
        FD_SET(sock[i], &rset);
        if (sock[i] > maxfdp)
            maxfdp = sock[i];
    }

    // Timeout {1Hour} if something goes wrong! (Maybe  mahimahi error...!)
    maxfdp = maxfdp + 1;
    struct timeval timeout;
    timeout.tv_sec = 600;
    timeout.tv_usec = 0;
    int rc = select(maxfdp, &rset, NULL, NULL, &timeout);
    printf("%d,%s", errno, strerror(errno));
    /**********************************************************/
    /* Check to see if the select call failed.                */
    /**********************************************************/
    if (rc < 0)
    {
        DBGERROR("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=- select() failed =-=-=-=-=-=--=-=-=-=-=\n");
        return;
    }
    /**********************************************************/
    /* Check to see if the time out expired.                  */
    /**********************************************************/
    if (rc == 0)
    {
        DBGERROR("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-=-=-=-=- select() Timeout! =-=-=-=-=-=--=-=-=-=-=\n");
        return;
    }

    int sin_size = sizeof(struct sockaddr_in);
    while (flow_index < flow_num)
    {
        if (FD_ISSET(sock[flow_index], &rset))
        {
            int value = accept(sock[flow_index], (struct sockaddr *)&client_addr[flow_index], (socklen_t *)&sin_size);
            DBGMARK(5, 1, "Accept request from client!");
            if (value < 0)
            {
                perror("accept error\n");
                DBGMARK(0, 0, "sockopt: %s\n", strerror(errno));
                DBGMARK(0, 0, "sock::%d, index:%d\n", sock[flow_index], flow_index);
                close(sock[flow_index]);
                return;
            }
            sock_for_cnt[flow_index] = value;
            flows[flow_index].flowinfo.sock = value;
            flows[flow_index].dst_addr = client_addr[flow_index];
            // 创建data thread 发送数据
            if (pthread_create(&data_thread, NULL, DataThread, (void *)&flows[flow_index]) < 0)
            {
                close(sock[flow_index]);
                return;
            }

            // 创建控制线程和定时器线程
            if (flow_index == 0)
            {
                if (pthread_create(&cnt_thread, NULL, CntThread, (void *)info) < 0)
                {
                    perror("could not create control thread\n");
                    close(sock[flow_index]);
                    return;
                }
                if (pthread_create(&timer_thread, NULL, TimerThread, (void *)info) < 0)
                {
                    perror("could not create timer thread\n");
                    close(sock[flow_index]);
                    return;
                }
            }

            DBGPRINT(0, 0, "Server is Connected to the client...\n");
            flow_index++;
        }
    }
    pthread_join(data_thread, NULL);
}

void *TimerThread(void *information)
{
    uint64_t start = timestamp();
    unsigned int elapsed;
    if ((duration != 0))
    {
        while (send_traffic)
        {
            sleep(1);
            elapsed = (unsigned int)((timestamp() - start) / 1000000); // unit s
            if (elapsed > duration)
            {
                send_traffic = false;
            }
        }
    }

    return ((void *)0);
}
void *CntThread(void *information)
{
    int ret1;
    double min_rtt_ = 0.0;
    double pacing_rate = 0.0;
    double lost_bytes = 0.0;
    double lost_rate = 0.0;
    double srtt_ms = 0.0;
    double snd_ssthresh = 0.0;
    double packets_out = 0.0;
    double retrans_out = 0.0;
    double max_packets_out = 0.0;

    int reuse = 1;
    int pre_id = 9230;
    int pre_id_tmp = 0;
    int msg_id = 657;
    bool got_alpha = false;
    bool slow_start_passed = 0;
    for (int i = 0; i < FLOW_NUM; i++)
    {
        if (setsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_NODELAY, &reuse, sizeof(reuse)) < 0)
        {
            DBGMARK(0, 0, "ERROR: set TCP_NODELAY option %s\n", strerror(errno));
            return ((void *)0);
        }
    }
    char message[1000];
    char *num;
    char *alpha;
    char *save_ptr;
    int got_no_zero = 0;
    uint64_t t0, t1;
    t0 = timestamp();
    info_length = sizeof(info_pre);
    for (int i = 0; i < FLOW_NUM; i++)
    {
        info_length = sizeof(info_pre);
        if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info_pre, &info_length) < 0)
        {
            DBGMARK(0, 0, "ERROR: getsockopt\n");
            return ((void *)0);
        }
        DBGMARK(5, 1, "\n!!!!!!!!!!!!!!!!!!!!!!!!\nthe congestion window at start = %u \n慢启动的阈值为 = %u \n",
                info_pre.tcpi_snd_cwnd, info_pre.tcpi_snd_ssthresh);
        // return ((void *)0);
    }
    int get_info_error_counter = 0;
    int actor_is_dead_counter = 0;
    int tmp_step = 0;
    int while_cnt = 0;
    unsigned int error_test = 10;
    while (send_traffic)
    {
        for (int i = 0; i < FLOW_NUM; i++)
        {
            got_no_zero = 0;
            usleep(report_period * 1000); // 20 * 1000 = 20000 us = 20 ms
            while (!got_no_zero && send_traffic)
            {
                info_length = sizeof(info);
                if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info, &info_length) < 0)
                {
                    DBGMARK(5, 1, "\n!!!!!!!!!!!!!!!!!!!!!!!!!!getsockopt11");
                    perror("getsockopt");
                }
                // if (orca_info.avg_urtt > 0)
                // DBGMARK(0, 0, "info.tcpi_rtt = %lf \n", (double)info.tcpi_rtt);
                if (info.tcpi_rtt >= 0)
                {
                    // DBGMARK(DBGSERVER, 1, "TCPI_RTT>0 extract the info and set cwnd \n");
                    t1 = timestamp();

                    double time_delta = (double)(t1 - t0) / 1000000.0;
                    // double delay = (double)orca_info.avg_urtt / 1000.0;
                    double delay = (double)info.tcpi_rtt / 1000.0;
                    // min_rtt_ = (double)(orca_info.min_rtt / 1000.0);
                    // ？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
                    min_rtt_ = (double)read_min_rtt(i);
                    // lost_bytes = (double)(orca_info.lost_bytes);
                    lost_bytes = (double)(info.tcpi_lost);
                    // pacing_rate = (double)(orca_info.pacing_rate);
                    pacing_rate = (double)info.tcpi_snd_cwnd / 20.0;
                    // lost_rate = lost_bytes / time_delta; // Rate in MBps
                    if (info.tcpi_snd_cwnd)
                    {
                        lost_rate = info.tcpi_lost / info.tcpi_snd_cwnd;
                    }
                    // srtt_ms = (double)((orca_info.srtt_us >> 3) / 1000.0);
                    srtt_ms = (double)((info.tcpi_rtt >> 3) / 1000.0);
                    // snd_ssthresh = (double)(orca_info.snd_ssthresh);
                    snd_ssthresh = (double)(info.tcpi_snd_ssthresh);
                    // packets_out = (double)(orca_info.packets_out);
                    packets_out = (double)(info.tcpi_unacked);
                    // retrans_out = (double)(orca_info.retrans_out);
                    retrans_out = (double)(info.tcpi_retrans);
                    // max_packets_out = (double)(orca_info.max_packets_out);
                    max_packets_out = (double)(info.tcpi_last_data_sent);

                    report_period = 20;
                    if (!slow_start_passed) // 如果慢启动还没过的话，若当前cwnd的大于阈值，则设置为1
                    {
                        slow_start_passed = (info.tcpi_snd_ssthresh < info.tcpi_snd_cwnd) ? 1 : 0;
                        // DBGMARK(5, 1, "\n当前的cwnd %u，cwnd阈值下降到%u \n", info.tcpi_snd_cwnd, info.tcpi_snd_ssthresh);
                        info_pre = info;
                        t0 = timestamp();
                        if (slow_start_passed)
                            DBGMARK(5, 1, "slow start passed!\n");
                        continue;
                    }
                    // if (!slow_start_passed) // 如果慢启动还没过的话，那么就是设置当前cwnd的1.1倍
                    // {
                    //     // got_no_zero=1;
                    //     // tcp_info_pre = orca_info;
                    //     info_pre = info;
                    //     t0 = timestamp();

                    //     // target_ratio = 1.1 * orca_info.cwnd;
                    //     target_ratio = 1.1 * info.tcpi_snd_cwnd;
                    //     DBGMARK(5, 1, "\n当前的要设置的cwnd %u，当前的cwnd阈值已经下降到%u \n", target_ratio, info.tcpi_snd_ssthresh);
                    //     // set_cwnd(target_ratio, i);
                    //     // if(set_if_out) return ((void *)0);
                    //     continue;
                    // }
                    // if(slow_start_passed){
                    //     DBGMARK(5, 1, "\n 已经过了slow_start!!!!!!!!! %u \n", target_ratio);
                    //     return ((void *)0);
                    // }
                    double anole_thr = 0;
                    if (time_delta)
                    {
                        anole_thr = (double)info.tcpi_snd_cwnd / time_delta;
                    }
                    sprintf(message, "%d %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f %.7f",
                            msg_id, delay, anole_thr, (double)10.0, (double)time_delta,
                            (double)target, (double)info.tcpi_snd_cwnd, pacing_rate, lost_rate, srtt_ms, snd_ssthresh, packets_out, retrans_out, max_packets_out, (double)info.tcpi_snd_mss, min_rtt_);
                    memcpy(shared_memory, message, sizeof(message));
                    if ((duration_steps != 0))
                    {
                        step_it++;
                        if (step_it > duration_steps)
                            send_traffic = false;
                    }

                    msg_id = (msg_id + 1) % 1000;
                    DBGPRINT(DBGSERVER, 1, "%s\n", message);
                    got_no_zero = 1;
                    // tcp_info_pre = orca_info;
                    info = info_pre;
                    t0 = timestamp();
                    get_info_error_counter = 0;
                }
                else
                {
                    get_info_error_counter++;
                    if (get_info_error_counter > 30000)
                    {
                        DBGMARK(0, 0, "No valid state for 1 min. We (server of Actor %d) are going down down down ...\n", actor_id);
                        send_traffic = false;
                    }
                    usleep(report_period * 100);
                }
            }
            /******************************************逻辑***************************************/
            /*************************************Evaluaiton stage********************************/
            while_cnt++;
            DBGMARK(5, 1, "\n这是第 %u 次在循环\n", while_cnt);
            info_length = sizeof(info_cur);
            if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info_cur, &info_length) < 0)
            {
                DBGMARK(5, 1, "\ngetsockopt_error\n");
                perror("getsockopt");
            }
            cur_cl_cwnd = info_cur.tcpi_snd_cwnd;
            // 读取cl和rl的cwnd, cur_rl_cwnd
            num = strtok_r(shared_memory_rl, " ", &save_ptr);
            alpha = strtok_r(NULL, " ", &save_ptr);
            if (num != NULL && alpha != NULL)
            {
                pre_id_tmp = atoi(num);
                cur_rl_cwnd = atoi(alpha);
                if (pre_id != pre_id_tmp /*&& target_ratio!=OK_SIGNAL*/)
                {
                    got_alpha = true;
                    pre_id = pre_id_tmp;
                    // cur_rl_cwnd = atoi(alpha) * get_cur_cwnd(i) / 100;
                    cur_rl_cwnd = atoi(alpha) * cur_cl_cwnd / 100;
                }

                if (target_ratio < MIN_CWND)
                    target_ratio = MIN_CWND;
            }
            // std::random_device rd;  // 随机数种子
            // std::mt19937 gen(rd()); // 基于 Mersenne Twister 的生成器
            // // 定义随机数分布范围 [150, 200]
            // std::uniform_int_distribution<> distrib(150, 200);
            // // 生成随机数
            // cur_rl_cwnd = distrib(gen);
            DBGMARK(5, 1, "\ncl = %u, rl = %u, prev = %u\n", cur_cl_cwnd, cur_rl_cwnd, cur_prev_cwnd);
            // error_test = error_test * 1.1;
            // set_cwnd(error_test, i);
            // usleep(80 * 1000); // 0.5RTT
            // 这里应该小流先开始，先简略，先cl后rl

            // cl小的情况
            if(cur_cl_cwnd <= cur_rl_cwnd){
                // 先cl 总共0.5RTT
                set_cwnd(cur_cl_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY); // 0.5RTT

                // 后rl 总共0.5RTT
                set_cwnd(cur_rl_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY * (2 * epsilon - 1)); // 按照epsilon来
                // Uprev
                DBGMARK(5, 1, "\n!!!!!!!!!!!!!!!!!!!!!Uprev!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                uprev = utility_value_module(cur_prev_cwnd, &is_right_prev, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY * (2 - 2 * epsilon)); // 按照epsilon来

                // prev 1个RTT
                set_cwnd(cur_prev_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY * epsilon); // 0.25RTT
                // Ucl
                DBGMARK(5, 1, "\n******************Ucl********************\n");
                ucl = utility_value_module(cur_cl_cwnd, &is_right_cl, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY); // 0.5RTT
                
                // Url
                DBGMARK(5, 1, "\n&&&&&&&&&&&&&&&&&&Url&&&&&&&&&&&&&&&&&&&&\n");
                url = utility_value_module(cur_rl_cwnd, &is_right_rl, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY * (1 - epsilon)); // 0.25RTT
            }else{ // rl小的情况
                // 先rl 总共0.5RTT
                set_cwnd(cur_rl_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY); // 0.5RTT

                // 后cl 总共0.5RTT
                set_cwnd(cur_cl_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY * (2 * epsilon - 1));  // 按照epsilon来
                // Uprev
                DBGMARK(5, 1, "\n!!!!!!!!!!!!!!!!!!!!!Uprev!!!!!!!!!!!!!!!!!!!!!!!!!\n");
                uprev = utility_value_module(cur_prev_cwnd, &is_right_prev, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY * (2 - 2 * epsilon)); // 按照epsilon来

                // prev 1个RTT
                set_cwnd(cur_prev_cwnd, i);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY * epsilon); // 0.25RTT
                // Url
                DBGMARK(5, 1, "\n&&&&&&&&&&&&&&&&&&Url&&&&&&&&&&&&&&&&&&&&\n");
                url = utility_value_module(cur_rl_cwnd, &is_right_rl, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY); // 0.5RTT
                
                // Url
                DBGMARK(5, 1, "\n******************Ucl********************\n");
                ucl = utility_value_module(cur_cl_cwnd, &is_right_cl, i);
                print_rtt(i);
                usleep(ONE_WAY_DELAY * (1 - epsilon)); // 0.25RTT
            }
            
            /*************************************计算最优速率********************************/
            int sum_right = 0;
            if (is_right_cl)
                sum_right++;
            if (is_right_rl)
                sum_right++;
            if (is_right_prev)
                sum_right++;
            change_to_abc();
            cal_optimal_cwnd(4 - sum_right);
            confidence_value_module(ucl, u_optimal, &eta_cl);
            confidence_value_module(url, u_optimal, &eta_rl);

            /**************************Probing Stage || Acceleration Stage************************/
            DBGMARK(5, 1, "\nUcl = %.4lf, Url = %.4lf, Uprev = %.4lf\n", ucl, url, uprev);
            DBGMARK(5, 1, "\neta_cl = %.4lf, eta_rl = %.4lf\n", eta_cl, eta_rl);
            if (eta_cl >= ETA_OFF && eta_rl >= ETA_OFF)
            { // Probing Stage
                info_length = sizeof(info);
                if (getsockopt(sock_for_cnt[i], IPPROTO_TCP, TCP_INFO, &info, &info_length) < 0)
                {
                    DBGMARK(5, 1, "\n!!!!!!!!!!!!!!!!!!!!!!!!!!getsockopt11");
                    perror("getsockopt");
                }
                set_cwnd(optimal_cwnd, i);
                cur_prev_cwnd = optimal_cwnd;
                // usleep(ONE_WAY_DELAY * 4 * 1000); // 2RTT
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY);
                ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                usleep(ONE_WAY_DELAY);
            }
            else
            { // Acceleration Stage 测试的时候可以暂时先不加
                // 这样写考虑了两个速率当时失效的情况
                bool flag_cl, flag_rl;
                if(eta_cl < ETA_OFF) flag_cl = false;
                else flag_cl = true;
                if(eta_rl < ETA_OFF) flag_rl = false;
                else flag_rl = true;

                while(!flag_cl || !flag_rl){ 
                    if(!flag_cl){
                        eta_cl += DELTA_ETA;
                        if(eta_cl >= ETA_ON) flag_cl = true;
                    }
                    if(!flag_rl){
                        eta_rl += DELTA_ETA;
                        if(eta_rl >= ETA_ON) flag_rl = true;
                    }
                    __u32 minrtt = read_min_rtt(i);
                    __u32 currtt = read_cur_rtt(i);
                    if(double(1.0 * currtt / minrtt) > 1 + MU) optimal_cwnd -= 1;
                    else optimal_cwnd += 1;
                    DBGMARK(5, 1, "\nminrtt = %u, currtt = %u, 比例 = %.4lf\n", minrtt, currtt, double(1.0 * minrtt / currtt));
                    
                    set_cwnd(optimal_cwnd, i);
                    cur_prev_cwnd = optimal_cwnd;
                    ONE_WAY_DELAY = read_cur_rtt(i) / 2;
                    usleep(ONE_WAY_DELAY);
                    DBGMARK(5, 1, "\neta_cl = %.4lf, eta_rl = %.4lf\n", eta_cl, eta_rl);
                }
            }
        }
    }
    shmdt(shared_memory);
    shmctl(shmid, IPC_RMID, NULL);
    shmdt(shared_memory_rl);
    shmctl(shmid_rl, IPC_RMID, NULL);
    return ((void *)0);
}

// DataThread中发送数据
void *DataThread(void *info)
{
    /*
    struct sched_param param;
    param.__sched_priority=sched_get_priority_max(SCHED_RR);
    int policy=SCHED_RR;
    int s = pthread_setschedparam(pthread_self(), policy, &param);
    if (s!=0)
    {
        DBGERROR("Cannot set priority (%d) for the Main: %s\n",param.__sched_priority,strerror(errno));
    }

    s = pthread_getschedparam(pthread_self(),&policy,&param);
    if (s!=0)
    {
        DBGERROR("Cannot get priority for the Data thread: %s\n",strerror(errno));
    }*/
    // pthread_t send_msg_thread;

    cFlow *flow = (cFlow *)info;
    int sock_local = flow->flowinfo.sock;
    char *src_ip;
    char write_message[BUFSIZ + 1];
    char read_message[1024] = {0};
    int len;
    char *savePtr;
    char *dst_addr;
    u64 loop;
    u64 remaining_size;

    memset(write_message, 1, BUFSIZ);
    write_message[BUFSIZ] = '\0';
    /**
     * Get the RQ from client : {src_add} {flowid} {size} {dst_add}
     */
    len = recv(sock_local, read_message, 1024, 0);
    if (len <= 0)
    {
        DBGMARK(DBGSERVER, 1, "recv failed! \n");
        close(sock_local);
        return 0;
    }
    /**
     * For Now: we send the src IP in the RQ to!
     */
    src_ip = strtok_r(read_message, " ", &savePtr);
    if (src_ip == NULL)
    {
        // discard message:
        DBGMARK(DBGSERVER, 1, "id: %d discarding this message:%s \n", flow->flowinfo.flowid, savePtr);
        close(sock_local);
        return 0;
    }
    char *isstr = strtok_r(NULL, " ", &savePtr);
    if (isstr == NULL)
    {
        // discard message:
        DBGMARK(DBGSERVER, 1, "id: %d discarding this message:%s \n", flow->flowinfo.flowid, savePtr);
        close(sock_local);
        return 0;
    }
    flow->flowinfo.flowid = atoi(isstr);
    char *size_ = strtok_r(NULL, " ", &savePtr);
    flow->flowinfo.size = 1024 * atoi(size_);
    DBGPRINT(DBGSERVER, 4, "%s\n", size_);
    dst_addr = strtok_r(NULL, " ", &savePtr);
    if (dst_addr == NULL)
    {
        // discard message:
        DBGMARK(DBGSERVER, 1, "id: %d discarding this message:%s \n", flow->flowinfo.flowid, savePtr);
        close(sock_local);
        return 0;
    }
    char *time_s_ = strtok_r(NULL, " ", &savePtr);
    char *endptr;
    start_of_client = strtoimax(time_s_, &endptr, 10);
    got_message = 1;
    DBGPRINT(DBGSERVER, 2, "Got message: %" PRIu64 " us\n", timestamp());
    flow->flowinfo.rem_size = flow->flowinfo.size;
    DBGPRINT(DBGSERVER, 2, "time_rcv:%" PRIu64 " get:%s\n", start_of_client, time_s_);

    // Get detailed address
    strtok_r(src_ip, ".", &savePtr);
    if (dst_addr == NULL)
    {
        // discard message:
        DBGMARK(DBGSERVER, 1, "id: %d discarding this message:%s \n", flow->flowinfo.flowid, savePtr);
        close(sock_local);
        return 0;
    }

    // Calculate loops. In each loop, we can send BUFSIZ (8192) bytes of data
    loop = flow->flowinfo.size / BUFSIZ * 1024;
    // Calculate remaining size to be sent
    remaining_size = flow->flowinfo.size * 1024 - loop * BUFSIZ;
    // Send data with 8192 bytes each loop
    DBGPRINT(0, 0, "Server is sending the traffic ...\n");

    // for(u64 i=0;i<loop;i++)
    while (send_traffic)
    {
        len = strlen(write_message);
        DBGMARK(DBGSERVER, 5, "len = %d\n", len);
        while (len > 0)
        {
            DBGMARK(DBGSERVER, 5, "++++++\n");
            int s = send(sock_local, write_message, strlen(write_message), 0);
            DBGMARK(DBGSERVER, 5, "Successfully sent = %d\n", s);
            len -= s;
            usleep(50);
            DBGMARK(DBGSERVER, 5, "------\n");
        }
        usleep(100);
    }
    flow->flowinfo.rem_size = 0;
    done = true;
    DBGPRINT(DBGSERVER, 1, "done=true\n");
    close(sock_local);
    DBGPRINT(DBGSERVER, 1, "done\n");
    return ((void *)0);
}
