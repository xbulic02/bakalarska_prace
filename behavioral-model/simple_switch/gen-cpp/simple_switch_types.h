/**
 * Autogenerated by Thrift Compiler (1.0.0-dev)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef simple_switch_TYPES_H
#define simple_switch_TYPES_H

#include <iosfwd>

#include <thrift/Thrift.h>
#include <thrift/TApplicationException.h>
#include <thrift/TBase.h>
#include <thrift/protocol/TProtocol.h>
#include <thrift/transport/TTransport.h>

#include <thrift/stdcxx.h>


namespace sswitch_runtime {

struct MirroringOperationErrorCode {
  enum type {
    SESSION_NOT_FOUND = 1
  };
};

extern const std::map<int, const char*> _MirroringOperationErrorCode_VALUES_TO_NAMES;

std::ostream& operator<<(std::ostream& out, const MirroringOperationErrorCode::type& val);

class MirroringSessionConfig;

class InvalidMirroringOperation;

typedef struct _MirroringSessionConfig__isset {
  _MirroringSessionConfig__isset() : port(false), mgid(false) {}
  bool port :1;
  bool mgid :1;
} _MirroringSessionConfig__isset;

class MirroringSessionConfig : public virtual ::apache::thrift::TBase {
 public:

  MirroringSessionConfig(const MirroringSessionConfig&);
  MirroringSessionConfig& operator=(const MirroringSessionConfig&);
  MirroringSessionConfig() : port(0), mgid(0) {
  }

  virtual ~MirroringSessionConfig() throw();
  int32_t port;
  int32_t mgid;

  _MirroringSessionConfig__isset __isset;

  void __set_port(const int32_t val);

  void __set_mgid(const int32_t val);

  bool operator == (const MirroringSessionConfig & rhs) const
  {
    if (__isset.port != rhs.__isset.port)
      return false;
    else if (__isset.port && !(port == rhs.port))
      return false;
    if (__isset.mgid != rhs.__isset.mgid)
      return false;
    else if (__isset.mgid && !(mgid == rhs.mgid))
      return false;
    return true;
  }
  bool operator != (const MirroringSessionConfig &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const MirroringSessionConfig & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  virtual void printTo(std::ostream& out) const;
};

void swap(MirroringSessionConfig &a, MirroringSessionConfig &b);

std::ostream& operator<<(std::ostream& out, const MirroringSessionConfig& obj);

typedef struct _InvalidMirroringOperation__isset {
  _InvalidMirroringOperation__isset() : code(false) {}
  bool code :1;
} _InvalidMirroringOperation__isset;

class InvalidMirroringOperation : public ::apache::thrift::TException {
 public:

  InvalidMirroringOperation(const InvalidMirroringOperation&);
  InvalidMirroringOperation& operator=(const InvalidMirroringOperation&);
  InvalidMirroringOperation() : code((MirroringOperationErrorCode::type)0) {
  }

  virtual ~InvalidMirroringOperation() throw();
  MirroringOperationErrorCode::type code;

  _InvalidMirroringOperation__isset __isset;

  void __set_code(const MirroringOperationErrorCode::type val);

  bool operator == (const InvalidMirroringOperation & rhs) const
  {
    if (!(code == rhs.code))
      return false;
    return true;
  }
  bool operator != (const InvalidMirroringOperation &rhs) const {
    return !(*this == rhs);
  }

  bool operator < (const InvalidMirroringOperation & ) const;

  uint32_t read(::apache::thrift::protocol::TProtocol* iprot);
  uint32_t write(::apache::thrift::protocol::TProtocol* oprot) const;

  virtual void printTo(std::ostream& out) const;
  mutable std::string thriftTExceptionMessageHolder_;
  const char* what() const throw();
};

void swap(InvalidMirroringOperation &a, InvalidMirroringOperation &b);

std::ostream& operator<<(std::ostream& out, const InvalidMirroringOperation& obj);

} // namespace

#endif
