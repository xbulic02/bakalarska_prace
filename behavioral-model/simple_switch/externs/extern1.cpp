#include "extern1.h"

  void ExternCounter::reset() {
    count = init_count_;
  }

  void ExternCounter::setInitCount(const Data &d){
    init_count = d;
  }

  void ExternCounter::init(){
    init_count_ = init_count.get<size_t>();
    reset();
  }

  void ExternCounter::increment() {
      count++;
      printf("count %d\n",count);
  }

  void ExternCounter::increment_by(const Data &d) {
    count += d.get<size_t>();
  }

  size_t ExternCounter::get() const {
    return count;
  }
  BM_REGISTER_EXTERN(ExternCounter);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, increment);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, init);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, increment_by, const Data &);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, reset);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, setInitCount, const Data &);
  BM_REGISTER_EXTERN_METHOD(ExternCounter, get);

  int import_extern_example(){ return 0;}
