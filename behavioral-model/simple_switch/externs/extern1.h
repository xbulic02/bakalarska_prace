#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/P4Objects.h>

#include <string>
#include <utility>
#include <vector>
#include <cassert>

using namespace std;
using namespace bm;
using bm::ExternFactoryMap;
using bm::packet_id_t;
using bm::p4object_id_t;

#ifndef EXTERN1_H
#define EXTERN1_H

int import_extern_example();

class ExternCounter : public ExternType {
 public:

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(init_count);
  }
    void reset();
    void setInitCount(const Data &d);
    void init() override;
    void increment();
    void increment_by(const Data &d);
    size_t get() const ;

 private:
  // declared attributes
  Data init_count;

  size_t init_count_{0};
  size_t count{0};
};

#endif