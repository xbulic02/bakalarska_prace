/**
 * Autogenerated by Thrift Compiler (0.9.2)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef simple_switch_TYPES_H
#define simple_switch_TYPES_H

#include <iosfwd>

#include <thrift/Thrift.h>
#include <thrift/TApplicationException.h>
#include <thrift/protocol/TProtocol.h>
#include <thrift/transport/TTransport.h>

#include <thrift/cxxfunctional.h>


namespace sswitch_runtime {

struct MirroringOperationErrorCode {
  enum type {
    SESSION_NOT_FOUND = 1
  };
};

extern const std::map<int, const char*> _MirroringOperationErrorCode_VALUES_TO_NAMES;

class MirroringSessionConfig;

class InvalidMirroringOperation;

typedef struct _MirroringSessionConfig__isset {
  _MirroringSessionConfig__isset() : port(false), mgid(false) {}
  bool port :1;
  bool mgid :1;
} _MirroringSessionConfig__isset;

class MirroringSessionConfig {
 public:

  static const char* ascii_fingerprint; // = "C1241AF5AA92C586B664FD41DC97C576";
  static const uint8_t binary_fingerprint[16]; // = {0xC1,0x24,0x1A,0xF5,0xAA,0x92,0xC5,0x86,0xB6,0x64,0xFD,0x41,0xDC,0x97,0xC5,0x76};

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

  friend std::ostream& operator<<(std::ostream& out, const MirroringSessionConfig& obj);
};

void swap(MirroringSessionConfig &a, MirroringSessionConfig &b);

typedef struct _InvalidMirroringOperation__isset {
  _InvalidMirroringOperation__isset() : code(false) {}
  bool code :1;
} _InvalidMirroringOperation__isset;

class InvalidMirroringOperation : public ::apache::thrift::TException {
 public:

  static const char* ascii_fingerprint; // = "8BBB3D0C3B370CB38F2D1340BB79F0AA";
  static const uint8_t binary_fingerprint[16]; // = {0x8B,0xBB,0x3D,0x0C,0x3B,0x37,0x0C,0xB3,0x8F,0x2D,0x13,0x40,0xBB,0x79,0xF0,0xAA};

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

  friend std::ostream& operator<<(std::ostream& out, const InvalidMirroringOperation& obj);
};

void swap(InvalidMirroringOperation &a, InvalidMirroringOperation &b);

} // namespace

#endif
