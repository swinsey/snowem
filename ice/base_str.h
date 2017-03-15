
#ifndef _TFC_BASE_STR_HPP_
#define _TFC_BASE_STR_HPP_

#include <string>
#include <sstream>
#include <vector>
#include <sys/time.h>
#include <stdlib.h>

namespace mqf { namespace base {

//////////////////////////////////////////////////////////////////////////

template<typename T> std::string to_str(const T& t)
{
	std::ostringstream s;
	s << t;
	return s.str();
}

template<typename T> T from_str(const std::string& s)
{
	std::istringstream is(s);
	T t;
	is >> t;
	return t;
}

inline void sran()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
}

inline unsigned int ran(unsigned range)
{
	unsigned r = rand() | (rand() << 16);
	r = r%range;
	//r = (unsigned) ( (0.0+range) * (r+0.0) / (ULONG_MAX+1.0));
	//cerr << "ran " << r << endl;
	return r;
}

//
//template<typename T> std::string operator+(const std::string& left, T& right)
//{
//	return left + to_str(right);
//}
//
//template<typename T> std::string operator+(T& left, const std::string& right)
//{
//	return to_str(left) + right;
//}

inline int split_conf_string(std::vector<std::string>& vtDst, const std::string& sSrc, std::string sep)
{
    if (sSrc.empty())
    {
        return 0;
    }

    std::string tmp;
    std::string::size_type pos_begin = sSrc.find_first_not_of(sep);
    std::string::size_type comma_pos = 0;

    unsigned int uiCount = 0;
    const unsigned int uiMaxCount = 1000;
    while (pos_begin != std::string::npos)
    {
        ++uiCount;
        if (uiCount > uiMaxCount)
        {
            break;
        }

        comma_pos = sSrc.find(sep, pos_begin);
        if (comma_pos != std::string::npos)
        {
            tmp = sSrc.substr(pos_begin, comma_pos - pos_begin);
            pos_begin = comma_pos + sep.length();
        }
        else
        {
            tmp = sSrc.substr(pos_begin);
            pos_begin = comma_pos;
        }

        if (!tmp.empty())
        {
            vtDst.push_back(tmp);
            tmp.clear();
        }
    }
    return 0;
}

}}	
#endif//_BASE_STR_HPP_
