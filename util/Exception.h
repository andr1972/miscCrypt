#pragma once
#include <stdlib.h>
#include <string.h>

namespace dcpcrypt {

class Exception
{
private:
    char *msgbuf;
    int n;
public:
    Exception(const std::string _message = "unknown", int _n=0) throw()
    {
      if (_message=="")
      {
          msgbuf = NULL;
          return;
      }
      size_t len = _message.length();
      msgbuf = (char*)malloc(len+1);
      if (!msgbuf) return;
      strcpy(msgbuf, _message.c_str());
    }
    virtual ~Exception() throw(){free(msgbuf);}
    // Returns a C-style character string describing the general cause
    //  of the current error.
    virtual const char* what() const throw() {return msgbuf;}
};

class EDCP_hash : public Exception {
public:
	EDCP_hash(const std::string _message = "unknown", int _n = 0) :Exception(_message, _n) {}
};
class EDCP_cipher : public Exception {
public:
	EDCP_cipher(const std::string _message = "unknown", int _n = 0) :Exception(_message, _n) {}
};
class EDCP_blockcipher : public EDCP_cipher {
public:
	EDCP_blockcipher(const std::string _message = "unknown", int _n = 0) :EDCP_cipher(_message, _n) {}
};

}