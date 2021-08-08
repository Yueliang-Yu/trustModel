#include "Packet.h"
int Packet::pnum;//自增变量，用于自动生成包号

//void Packet::setBirth(int time)
//{	//设置包产生的时间
//	birth = time;
//}

Packet::Packet()
{
	this->source = EMPTY_PACK;
	this->destination = EMPTY_PACK;
	this->packType = EMPTY_PACK;
}

Packet::Packet(int sou, int des, int type, int birTime)
{
	this->pno = ++pnum;
	this->source = sou;
	this->destination = des;
	this->packType = type;
	ifstream fin(SCALE_PATH, ios::in);
	int thingNum;
	fin >> thingNum;
	//初始化一个没有内容的空包
	map<int, double> a;
	this->packBody = a;

	//初始化时延在[5, 20)之间
	srand((unsigned)clock());
	this->delay = random(15) + 5;

	//打包时间
	this->birth = birTime;

	this->sender = sou;
	this->lastSender = -1;
}

void Packet::setSender(int s)
{
	sender = s;
}

int Packet::getSender()
{
	return sender;
}

void Packet::setLastSender(int s)
{
	lastSender = s;
}

int Packet::getLastSender()
{
	return lastSender;
}

void Packet::setPackBody(map<int, double> data)
{
	//设置包体
	this->packBody = data;
}

int Packet::getPno()
{
	return pno;
}

int Packet::getSource()
{
	return source;
}

int Packet::getDestination()
{
	return destination;
}

int Packet::getPackType()
{
	return packType;
}

int Packet::getBirth()
{
	return birth;
}

int Packet::getDelay()
{
	return delay;
}

map<int, double> Packet::getData()
{
	return packBody;
}

void Packet::printPacket()
{
	printf("-----------------------------------------\n");
	printf("包号：%d\n源地址：%d\n目的地址：%d\n时延：%d\n产生时间：%d\n类型：%d\n"
		,pno, source, destination, delay, birth, packType);
	printf("包体：\n");
	for (map<int, double>::iterator it = packBody.begin();
		it != packBody.end(); it++) {
		printf("%d处数据为%f\n", (*it).first, (*it).second);
	}
	printf("由:%d号结点转发经%d号节点\n", lastSender, sender);
	printf("-----------------------------------------\n");
}
