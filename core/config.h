#ifndef __TFC_BASE_CONFIG_H__
#define __TFC_BASE_CONFIG_H__

#include <string>
#include <map>
#include <vector>
#include <stdexcept>

using namespace std;

namespace mqf { namespace base {

struct conf_load_error: public runtime_error{ conf_load_error(const string& s):runtime_error(s){}};
struct conf_not_find: public runtime_error{ conf_not_find(const string& s):runtime_error(s){}};

class CConfig
{
public:
	CConfig(){}
	CConfig(const CConfig&);
	virtual ~CConfig(){}

public:
	/**
	 * @throw conf_load_error when Load fail
	 */
	virtual void Load()=0;

	/**
	 * @throw conf_not_find when Load fail
	 */
	virtual const string& operator [](const string& name) const = 0;

	virtual const map<string,string>& GetPairs(const string& path) const = 0;
	virtual const vector<string>& GetDomains(const string& path) const = 0;
	virtual const vector<string>& GetSubPath(const string& path) const = 0;
        virtual void Load(string& scontent) = 0; 
};

}}
#endif //

