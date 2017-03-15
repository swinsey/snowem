
#ifndef _CORE_CONFIG_FILE_H_
#define _CORE_CONFIG_FILE_H_

#include "config.h"

#include <deque>

using namespace std;

namespace mqf { namespace base {

class CFileConfig:public CConfig
{
public:
	CFileConfig();
	CFileConfig(const CFileConfig&);
        //no implementation
	virtual ~CFileConfig();

public:
	/**
	 * @throw conf_load_error when Load fail
	 * @param filename
	 */
	void Init(const string& filename) throw(conf_load_error);

	/**
	 * @throw conf_load_error when Load fail
	 */
	virtual void Load() throw (conf_load_error);

	/**
	 * @throw conf_not_find when Load fail
	 */
	virtual const string& operator [](const string& name) const throw(conf_not_find);
	virtual const map<string,string>& GetPairs(const string& path) const;
	virtual const vector<string>& GetDomains(const string& path) const;
	virtual const vector<string>& GetSubPath(const string& path) const;
        virtual void Load(string& scontent);
protected:
	enum EntryType {
		T_STARTPATH = 0,
		T_STOPPATH = 1,
		T_NULL = 2,
		T_PAIR = 3,
		T_DOMAIN =4,
		T_ERROR = 5
	};

	string start_path(const string& s);
	string stop_path(const string& s);
	void decode_pair(const string& s,string& name,string& value);
	string trim_comment(const string& s);
	string path(const deque<string>& path);
	string parent_path(const deque<string>& path);
	string sub_path(const deque<string>& path);

	EntryType entry_type(const string& s);
protected:
	string _filename;

	map<string,map<string,string> > _pairs;
	map<string,vector<string> > _paths;
	map<string,vector<string> > _domains;

	map<string,string> _null_map;
	vector<string> _null_vector;
};

}}
#endif // _CORE_CONFIG_FILE_H_


