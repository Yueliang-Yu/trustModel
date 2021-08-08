#include <algorithm>
#include "Node.h"
#include "packet.h"
#define oo 9999999
#define R 0.5
#define N 100
const int minpoints = 10;


Node::Node(int x, int y, int nodeNo, int nodeType, vector<double> data, int tolNode)
{
	this->no = nodeNo;
	set<int> s;
	this->pHistory = s;
	this->type = nodeType;

	this->x = x;
	this->y = y;

	//观测数据
	map<int, double> a;
	if (type < 0) {//边缘服务器获取初始数据
		srand((unsigned)clock());
		for (int i = 0; i < DATA_TYPE ; i++) {
			srand((unsigned)clock());
			//随机加减[-0.99, 1],模拟观测误差
			a[i] = data[i] + 1.0*(random(20) - 9) / 10;
			if (type == MALICIOUS_EDGE)
				a[i] += 1.0*(random(200) - 99) / 10;
			Sleep(1);
		}
		
	}
	else {//物层结点观测数据
		for (int i = 0; i < random(DATA_TYPE); i++) {
			srand((unsigned)clock());
			int place = random(DATA_TYPE);
			if (!this->data.count(place)) {
				a[place] = data[place] + 1.0*(random(200) - 99) / 10;
			}
			Sleep(1);
		}
	}
	this->data = a;
	Sleep(1);
	srand((unsigned)clock());
	//配置默认资源量
	if (nodeType < 0)
		//边缘服务器初始资源范围[150, 1000)
		this->resource = random(EDGE_RES - 150) + 150;
	else
		//物层结点初始资源范围[15,100)
		this->resource = random(THING_RES - 15) + 15;

	//初始化数据信任,避免冷启动记录初值
	this->dataTrust.assign(tolNode, INIT_DATA_TRUST);

	//初始化边缘服务器的数据缓冲区
	if (this->type < 0) {
		//缓冲区存放物层结点提供的数据，聚类判断善意数据以后才存入自己的数据里
		//其实DATA_TYPE×ThingNodeNum的大小就够
		vector<vector<double> > t(DATA_TYPE, vector<double>(tolNode, NoDATA));
		this->dataBuffer = t;
		this->dataTimeLimit.assign(DATA_TYPE, 0);
	}
}

int Node::getNo()
{
	return no;
}

int Node::getResource()
{
	return resource;
}

int Node::nodeType ()
{
	return type;
}

unordered_map<int, RIPRow> Node::getRIPTable()
{
	return this->ripTable;
}

void Node::printRIPTable()
{
	cout << this->no << "结点的RIP路由表：\n";
	cout << "目的地址|下一跳|距离\n";
	for(auto &i : this->ripTable)
		cout << i.second.getDestination() << '\t'
			<< i.second.getNextNode() << '\t'
			<< i.second.getDistance() << '\n';
}

void Node::updateRIPTable(int neighbor, unordered_map<int, RIPRow> neighborRIP)
{
	//根据邻居的路由表更新自己的路由表
	for (unordered_map<int, RIPRow>::iterator it = neighborRIP.begin();it != neighborRIP.end(); it++) 
    {
		RIPRow rip = it->second;
		auto myRip = ripTable.find(it->first);		//在自己的路由里查找这个目的地址
		if (rip.getDistance() + 1 == OUT_OF_RANGE)	//不可达的记录
			continue;
		if (rip.getDestination() == this->no)		//不记录自身
			continue;
		if (myRip != ripTable.end()) {
			//已经存有到达这一目的地址的记录,取跳数小者
			int dis = rip.getDistance();
			if (dis + 1 < myRip->second.getDistance()) {
				rip.addOneJumpDistance();
				rip.setNextNode(neighbor);
				myRip->second = rip;
			}
		}
		else {
			//尚未记录的结点，加入路由表
			rip.addOneJumpDistance();
			rip.setNextNode(neighbor);
			this->ripTable.insert(pair<int, RIPRow>(it->first, rip));
		}
	}
}

void Node::setNeighbourNum(int heighbourNum)
{
	this->neighbourNum = neighbourNum;
}

void Node::setCrossLayerAssociation(list<int> nodelist)
{
	//设置跨层关联结点，如服务器结点利用其记录范围内的物层
	for (list<int>::iterator it = nodelist.begin(); it != nodelist.end(); it++)
		this->crossLayerAssociation.push_back(*it);
}

void Node::addRIPRow(RIPRow r)
{
	//添加一条表项记录
	this->ripTable.insert(pair<int, RIPRow>(r.getDestination(), r));
}

int Node::searchRIP(int destination)
{
	//到达destination的下一跳结点，若路由表中没有到des的记录返回-1
	for (unordered_map<int, RIPRow>::iterator it = this->ripTable.begin();
		it != this->ripTable.end(); it++) {
		if (it->second.getDestination() == destination
			&& it->second.getDistance() < OUT_OF_RANGE)
			return it->second.getNextNode();
	}
	return -1;
}

unordered_map<int, RIPRow> Node::getRIPtable()
{
	return this->ripTable;
}

vector<int> Node::getCrossLayerAssociation()
{//获取该结点的跨层关联，即服务器范围内的物层结点或物层结点连接的服务器
	return this->crossLayerAssociation;
}

int Node::getCrossLayerAssociationNum()
{
	return this->crossLayerAssociation.size();
}

int Node::getX()
{
	return this->x;
}

int Node::getY()
{
	return this->y;
}

int Node::getNeighbourNum()
{
	return this->neighbourNum;
}

double Node::getData(int require)
{
	//查找请求的数据，有则返回该数据，无则返回-1
	if (data.count(require))
		return data[require];
	return DATA_NOT_FOUND;
}

void Node::printRes()
{
	//打印结点资源利用率
	cout << no << "  结点类型：";
	if (type < 0)
		cout << "边缘服务器\n  资源余量占比："<<100.0*resource/EDGE_RES << "%\n";
	else
		cout << "物层结点\n  资源余量占比：" << 100.0*resource / THING_RES << "%\n";
}

void Node::printData()
{
	//打印结点持有的数据
	printf("%d号%d节点持有的数据情况如下：================\n", this->no,this->type);
	for (map<int, double>::iterator it = this->data.begin(); it != this->data.end(); it++) {
		printf("  %d处数据为%f\n", it->first, it->second);
	}
}

Packet Node::requireData(int place, int now)
{
	//向周围节点请求数据，des==-1表示广播包
	this->resChg((-1)*SEND_PACK_CONSUME);
	Packet p(this->no, -1, REQ_DATA, now);
	map<int, double> d;
	d.insert(make_pair(place, -1));
	p.setPackBody(d);
	this->sendBuffer.push(p);
	this->pHistory.insert(p.getPno());
	return p;
	////物层结点请求数据
	//if (this->type > 0) {
	//	Packet p(this->no, -1, REQ_DATA, now);
	//	
	//}
	//else {//边缘服务器请求数据
	//	Packet p(this->no, -1, REQ_DATA, now);
	//}
}

Packet Node::sendData(int place, double dataVal, int des, int now)
{
	Packet p(this->no, des, ANS_DATA, now);
	map<int, double> d;
	d.insert(make_pair(place, dataVal));
	p.setPackBody(d);
	this->sendBuffer.push(p);
	this->pHistory.insert(p.getPno());
	return p;
}

Packet Node::forwardPack(Packet p, int now)
{
	//资源不允许
	if (!this->freeToMove(now)) {
		return this->refusePack(p, now);
	}

	//恶意结点拒绝转包
	Sleep(1);
	srand((unsigned)clock());
	if (this->type == MALICIOUS_THING && 1.0*random(100) / 100 < F) {
		return this->refusePack(p, now);
	}

	//转包
	this->sendPacket(p);
	p.setLastSender(p.getSender());
	p.setSender(this->no);
	p.chgBirth(now + p.getDelay());//random模拟处理和收发包时延
#ifdef DEBUG
	printf("%d结点转发来自%d结点的%d号包\n", p.getSender(), p.getLastSender(), p.getPno());
#endif
	return p;
}

Packet Node::receivePack(Packet p, int now, vector<double> realData)
{
	//已经收过这个包或者这个包是自己发出的请求包，返回空包表示不对这个包做处理
	//目前本函数未考虑向特定结点请求包的情况，即默认请求数据的包目的地址都是-1
	if (this->pHistory.find(p.getPno()) != this->pHistory.end() ||
		(p.getSource() == this->no && p.getPackType() == REQ_DATA)) {
		return Packet();
	}

	this->pHistory.insert(p.getPno());
	map<int, double> d = p.getData();

	//接受自己的应答包，不考虑资源消耗
	if (p.getDestination() == this->no && p.getPackType() == ANS_DATA){
		//边缘服务器收包
		if (this->type < 0) {


			
		}
		//物层结点收包
		else {
			for (map<int, double>::iterator it = d.begin();
				it != d.end(); it++) {
				int place = (*it).first;
				double val = (*it).second;
				if (abs(realData[place] - val) < 1.1) {
					this->dataTrust[p.getSource()]++;
					this->data[(*it).first] = (*it).second;
				}
			}
		}
		return Packet();
	}

	//结点有空闲资源接收应答包
	else if (this->freeToMove(now) 
		&& p.getPackType() == ANS_DATA) {
		this->resChg((-1)*RECEIVE_PACK_CONSUME);
		this->receiveBuffer.push(p);
		return this->forwardPack(p, now);
	}

	//有空闲资源接收请求包
	if (this->freeToMove(now) && p.getPackType() == REQ_DATA) {
		this->receivePacket(p);

		//响应数据请求：
		if (p.getDestination() == -1 ||
			(p.getDestination() == no && p.getPackType() == REQ_DATA)) {
			bool flag = 0;//有无数据
			for (map<int, double>::iterator it = d.begin();
				it != d.end(); it++) {
				double myData = this->getData((*it).first);
				if (myData != DATA_NOT_FOUND) {
					flag = 1;
					(*it).second = myData;
#ifdef DEBUG
					printf("%d结点发送%d处数据%f给%d\n",
						no, (*it).first, (*it).second, p.getSource());
#endif
				}
			}
			//有所求数据
			if (flag) {
				Packet ans(this->no, p.getSource(), ANS_DATA, now);
				ans.setPackBody(d);
				ans.chgBirth(now + ans.getDelay());//模拟处理时延
				return ans;
			}
			//没有所求的数据，物层结点转包
			if (this->type > 0)
				return this->forwardPack(p, now);
		}
		//给别人的应答包：
		else {
			if (this->no > 0)	//物层结点转发
				return this->forwardPack(p, now);
			else				//边缘服务器不处理
				return Packet();
		}
	}
	//无空闲资源拒绝收包==拒绝转包：
	return this->refusePack(p, now);
}

Packet Node::refusePack(Packet p, int now)
{
	this->pHistory.erase(p.getPno());
	//加一个delay模拟处理时延
	return Packet(this->no, p.getSender(), REFUSEFORWARD, now + p.getDelay());
}

void Node::recover(int now)
{
	//随机恢复一定量的资源
	this->resChg(random(25));

	//发包缓冲区出包
	while (!sendBuffer.empty() &&
		sendBuffer.front().getBirth() + sendBuffer.front().getDelay()
		>= now) {
		this->resChg(SEND_PACK_CONSUME);
		sendBuffer.pop();
	}
	//收包缓冲区出包
	while (!receiveBuffer.empty() &&
		receiveBuffer.front().getBirth() + receiveBuffer.front().getDelay()
		>= now) {
		this->resChg(RECEIVE_PACK_CONSUME);
		receiveBuffer.pop();
	}
}

void Node::sendPacket(Packet p)
{
	this->sendBuffer.push(p);
	this->resChg((-1)*SEND_PACK_CONSUME);
}

void Node::receivePacket(Packet p)
{
	this->resChg((-1)*RECEIVE_PACK_CONSUME);
	this->receiveBuffer.push(p);
}

bool Node::freeToMove(int now)
{
	this->recover(now);

	//资源余量 > 10% 则继续收发包
	if (type < 0 && this->resource > EDGE_RES / 10)
		return true;
	if (type > 0 && this->resource > THING_RES / 10)
		return true;
	return false;
}


void Node:: resChg(int deltaRes)
{
	this->resource += deltaRes;
}
void Node::cleanpHistory()
{
	//清除当前结点的收包缓存
	this->pHistory.clear();
}

void Node::printDataTrust()
{
	int n = this->dataTrust.size();
	for (int i = 0; i < n; i++) {
		printf("%f ", this->dataTrust[i]);
	}
	printf("\n");
}

void judgeQos(int i,Packet p)
{
	if((p.getDelay()>SAT_DELAY)&&(p.getBandwidth()>SAT_BANDWIDTH) num_s[i]++;
	else num_us[i]++;
}

void Node::calServiceTrust(int i)
{
	Ts[i]=(num_s[i]+1)/(num_s[i]+num_us[i]+2);
}

void Node::calContentTrust(int i)
{
	Tc[i]=(num_c[i]+1)/(num_c[i]+num_uc[i]+2);
}

void Node::calHelpTrust(int i)
{
	Th[i]=(num_fw[i]+1)/(num_fw[i]+num_refw[i]+2);
}

void Node::calComprehensiveTrust(Node n,int i)//分类讨论 不同层的设备的直接信任不同
{
	if()
}