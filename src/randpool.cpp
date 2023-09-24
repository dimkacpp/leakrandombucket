#include "randpool.h"
#include <strings.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cstring>
#include <boost/exception/exception.hpp>
#include <boost/exception/diagnostic_information.hpp>

namespace sim {

RandPool::RandPool()
{
    init();
}

void RandPool::addPacket(struct pcap_pkthdr* header, const u_char* data)
{

    boost::lock_guard<boost::mutex> lk(m_mtx);

    if( header->caplen > MTU ) {
        throw std::logic_error("wrong MTU in frame");
    }

    if ( m_indexs.empty() ) {
        unsigned int random_index = std::rand()%BUFFCNT;
        m_main_pool.erase(m_accmasive[random_index]);
        m_accmasive[random_index] = m_main_pool.end();
        m_indexs.push(random_index);
    }

    unsigned int id =  m_indexs.front();
    m_indexs.pop();

    list_node_t node;
    node.m_id = id;
    void * tmpheader = operator new( sizeof( struct pcap_pkthdr ));
    void * tmpdata  = operator new( header->caplen );

    std::memcpy(tmpheader, header, sizeof(struct pcap_pkthdr) );
    std::memcpy(tmpdata, data, header->caplen);
    node.m_header.reset((struct pcap_pkthdr*)tmpheader);
    node.m_data.reset( (const u_char*)tmpdata );
    node.m_size = header->caplen;
    auto itr = m_main_pool.insert(m_main_pool.end(), std::move(node));
    m_accmasive[id] = itr;
    return;
}

uint64_t RandPool::processBySize(size_t size, std::function<void (pcap_pkthdr *, const u_char *)> callback)
{

    boost::lock_guard<boost::mutex> lk(m_mtx);
    size_t current_size = 0;
    while (  !m_main_pool.empty() && current_size < size ) {
        unsigned int indx = m_main_pool.front().m_id;
        auto itr = m_accmasive[ indx ];
        current_size += itr->m_size;
        if ( itr->m_size > MTU ) {
           throw std::logic_error("wrong frame size");
        }
        if ( current_size <= size ) {
            callback(itr->m_header.get(), itr->m_data.get());
            m_accmasive[ indx ] = m_main_pool.end();
            m_indexs.push(itr->m_id);
            m_main_pool.erase(itr);
        }
        else {
            return current_size -= itr->m_size;
        }
    }
    return current_size;

}

bool RandPool::empty()
{
    boost::lock_guard<boost::mutex> lk(m_mtx);
    return m_main_pool.empty();
}

void RandPool::init()
{
    std::srand(std::time(nullptr));
    for (unsigned int i = 0 ; i < BUFFCNT ; ++i ) {
        m_indexs.push(i);
    }
    bzero(m_accmasive, sizeof(m_accmasive));
}

}
