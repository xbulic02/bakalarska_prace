#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>
#include <boost/any.hpp>

#include <string>
#include <utility>
#include <vector>
#include <cassert>

#include "./externs/extern1.h"

using namespace std;
using namespace bm;
using bm::ExternFactoryMap;
using bm::packet_id_t;
using bm::p4object_id_t;

void testing();

class ExternRunner{

public:
    ExternRunner();
    ~ExternRunner();
    template<typename T> 
    T externInit(string externClass, map<string, Data> atributy);

};

// spousteni externu v kodu targetu
template<typename T>
T ExternRunner::externInit(string externClass, map<string, Data> atributy){

    auto externInstance = ExternFactoryMap::get_instance()->get_extern_instance(
       string(externClass));
    externInstance->_register_attributes();
    
    for (std::map<string, Data>::iterator it = atributy.begin(); it != atributy.end(); ++it){
        externInstance->_set_attribute<Data>(it->first, Data(it->second));
    }
    externInstance->init();

    T specificInstance = dynamic_cast <T> (externInstance.get());
    return specificInstance;
}
