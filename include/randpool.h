#ifndef RANDPOOL_H
#define RANDPOOL_H

#include <queue>
#include <list>
#include <chrono>
#include <pcap.h>
#include <functional>
#include <boost/thread/mutex.hpp>
#include <boost/thread/locks.hpp>
#include <memory>

//#define BUFFCNT 10000

namespace sim {



typedef struct {
    unsigned int m_id = 0;
    std::shared_ptr<const u_char> m_data;
    std::shared_ptr<struct pcap_pkthdr> m_header;
    size_t m_size;

} list_node_t;

typedef std::list<list_node_t> main_pool_t;
typedef main_pool_t::iterator main_pool_itr_t;

class RandPool
{
public:
    RandPool();
    void addPacket( struct pcap_pkthdr* header, const u_char* data);
    uint64_t processBySize( size_t size, std::function< void (struct pcap_pkthdr* , const u_char *) > callback );
    bool empty();
    void init();

private:
    std::queue<unsigned int> m_indexs;
    main_pool_itr_t m_accmasive[BUFFCNT];
    main_pool_t m_main_pool;
    boost::mutex m_mtx;
};

}

#endif // RANDPOOL_H
