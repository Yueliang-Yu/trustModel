//结点类
#include<iostream>
#include<list>
#include<set>
#include<queue>
#include<unordered_map> 
#include<Windows.h>
using namespace std;
#include "Packet.h"
const int THING_RES = 100;		//物层结点资源总量
const int EDGE_RES = 1000;		//边缘服务器资源总量
const int DATA_TYPE = 100;		//数据总量
const int DATA_RANGE = 50;			//数据范围
const double INIT_DATA_TRUST = 0;
const int NoDATA = DATA_RANGE+1;	//边缘缓冲区无数据的标记
//const int TIMELIMIT = 1000;		//数据时限，
//结点类型，负数为边缘服务器
const int COOPERATIVE_EDGE = -1;
const int MALICIOUS_EDGE = -2;
const int COOPERATIVE_THING = 1;
const int MALICIOUS_THING = 2;
constexpr auto REFUSEFORWARD = -2;
const double F = 0.5;			//灰洞结点不转包率
const int DATA_NOT_FOUND = -1;	//未找到数据

const double SAT_DELAY;
const double SAT_BANDWIDTH;
const double WD;
const double WI;

class Node {
private:
	int x;
	int y;
	int no;						//结点编号
	int resource;				//结点资源量
	int neighbourNum;			//邻居数
	unordered_map<int, RIPRow> ripTable;//路由表
	vector<int> crossLayerAssociation;	//跨层关联，物层结点记录其服务器，服务器记录其范围内的物层
	set<int> pHistory;			//存储收过的包
	map<int, double> data;
	vector<double> dataTrust;	//数据信任（收到的数据与真实值差异不大则记录一次信任）
	queue<Packet> sendBuffer;	//发包缓冲区
	queue<Packet> receiveBuffer;//收包缓冲区
	vector<vector<double> > dataBuffer;//边缘服务器的数据缓冲区
	
	int type;					//种类，2表示云层,1表示边缘服务器,0表示物层结点

	map<int,double> Ts //服务信任
	map<int,double> Tc //内容信任
	map<int,double> Th //合作信任
	
	map<int,int> num_s; //服务信任中满意的次数
	map<int,int> num_us; //服务信任中不满意的次数
	map<int,int> num_c; //内容信任中的满意次数
	map<int,int> num_nc; //内容信任中的不满意次数
	map<int,int> num_fw; //协作信任中的转发次数
	map<int,int> num_refw; //协作信任中的拒绝转发次数

public:
	Node(int x, int y, int nodeNo, int nodeType, vector<double> data, int tolNode);
	int getNo();
	int getResource();	//获取资源数量
	int nodeType();		//获取结点类型
	unordered_map<int, RIPRow> getRIPTable();//获取路由表
	void printRIPTable();//打印路由表
	void updateRIPTable(int neighbor, unordered_map<int, RIPRow> neighborRIP);//根据邻居的路由表更新路由表
	void setNeighbourNum(int heighbourNum);	//设置邻居结点数目
	void setCrossLayerAssociation(list<int> nodelist);//设置跨层关联
	void addRIPRow(RIPRow r);
	int searchRIP(int destination);//在路由表中搜索，要达到destination的下一跳结点
	unordered_map<int, RIPRow> getRIPtable();//获取路由表
	vector<int> getCrossLayerAssociation();	//获取该结点的跨层关联
	int getCrossLayerAssociationNum();		//获取跨层连接的结点数
	int getX();
	int getY();
	int getNeighbourNum();//获取邻居节点数目
	double getData(int require);		//查找请求的数据，有则返回该数据，无则返回-1
	void printRes();				//打印结点资源利用率
	void printData();				//打印结点持有的数据
	Packet requireData(int place, int now);	//向周围结点请求数据
	Packet sendData(int place, double dataVal, int des, int now);//给边缘服务器提供数据
	Packet forwardPack(Packet p, int now);	//发包
	Packet receivePack(Packet p, int now, vector<double> realData);	//收包
	Packet refusePack(Packet p, int now);	//拒绝收包
	void recover(int now);			//根据当前时间now，恢复消耗的资源
	void sendPacket(Packet p);		//发包
	void receivePacket(Packet p);	//收包
	bool freeToMove(int now);		//是否有能力收发包,资源余量>10%则继续收发包
	void resChg(int deltaRes);		//资源变动
	void cleanpHistory();			//清除当前结点的收包缓存
	void printDataTrust();			//边缘服务器输出数据信任

	void judgeQos(int i,Packet p);//判断上层提供服务的Qos 改变相应num_s num_us
	void calServiceTrust();//计算当前时间片中该节点的服务信任

	void calContentTrust(int i);//计算当前时间片中该节点对低层节点i的内容信任
	bool verifySign(); //伪签名函数 用随机数验证是否成功

	void calHelpTrust();//计算当前时间片中该节点的协作信任
	
	void calRecommendTrust(int i);//推荐信任

	void calComprehensiveTrust(Node n,int i);//综合信任
};

#endif