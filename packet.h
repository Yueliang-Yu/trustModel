#include<map>
#include<ctime>
#include<fstream>
using namespace std;
#define random(x) (rand()%x)	//[0, x)的随机值
const string SCALE_PATH = "scale.txt";//网络规模文件，存储物层和边缘层结点数量
const int REQ_DATA = 0;	//请求包
const int ANS_DATA = 1;	//应答包
const int RECEIVE_PACK_CONSUME = 17;	//收包消耗资源量
const int SEND_PACK_CONSUME = 13;	//发包消耗资源量
const int EMPTY_PACK = -10;			//空包标记
class Packet {
private:
	static int pnum;		//包数
	int pno;				//包号
	int source;				//源地址
	int destination;		//目的地址，-1表示广播包
	double delay;				//收发包时延
	double birth;				//包产生的时间
	double bandwidth;           //发送带宽
	int num_Qos;            //Qos参数数量
	map<int, double> packBody;	//包体，数据包的具体内容
	int packType;			//0表示请求数据，1表示发送数据,2表示反馈数据
	int lastSender;			//前一个发包结点
	int sender;				//发来这个包的结点，不是包的源地址
	int type;				//包来自层的种类，2表示云层,1表示边缘服务器,0表示物层结点

public:

	Packet();

	Packet(int sou, int des, int packType, int birTime);


	void setSender(int s);

	int getSender();

	void setLastSender(int s);

	int getLastSender();

	void setPackBody(map<int, double> data);

	int getPno();

	int getSource();

	int getDestination();

	int getPackType();

	int getBirth();

	int getDelay();

	int getBandwidth();
	
	map<int, double> getData();

	void printPacket();//打印包的内容


};

