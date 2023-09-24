#ifndef PCAPREADER_HPP
#define PCAPREADER_HPP

#include <string>
#include "randpool.h"

namespace sim {

class PcapReader {
public:
    bool processFile(const std::string & _file, const std::string & _path, RandPool& _rand_pool, float rate);
    bool processDump(std::string _file, RandPool *_rand_pool);
private:
     pcap_t * pcap = nullptr;
     pcap_dumper_t *pdump = nullptr;
     float m_rate = 0;
     bool m_terminate = false;

};

}

#endif // PCAPREADER_HPP
