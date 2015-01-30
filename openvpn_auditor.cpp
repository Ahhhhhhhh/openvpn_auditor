/*
Openvpn plugin. Records data usage of all accounts
usage in openvpn conf file:	plugin $0 [-s stats file path]
Output levels:	ERROR=0, WARNING=1, INFO=3, DEBUG=10

For license, see file LICENSE.
This plugin uses codes partially from:
	openvpn-2.3.6
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
extern "C"{
#include "openvpn/openvpn-plugin.h"
// #include "openvpn-plugin.h"
}
#include <unistd.h>
#include <stdarg.h>

#define PLUGIN_NAME	"AUDITOR"
#define PCLASS		auditor
#define ENDL		"\n"
// #define DEBUG
#ifdef DEBUG
#define O(X...)	fprintf(stderr,X);
#else
#define O(X...)
#endif

class plugin_base{
private:
protected:
	const char	*plugin_name;
	inline const char* get_localtime(time_t rawtime)
	{
		//return local time in ascii format
		struct tm	*timeinfo;
		char*		stime;
		timeinfo=localtime(&rawtime);
		stime=asctime(timeinfo);
		stime[strlen(stime)-1]=0;
		return stime;
	}
	inline const char* get_localtime()
	{
		//return local time in ascii format
		time_t		rawtime;
		time(&rawtime);
		return get_localtime(rawtime);
	}
	void log(FILE* fp,int lv,const char *envp[],const char format[],va_list arglist)
	{
		//write log with verb level lv to FILE fp, environment as envp. The rest follows printf format
		int lv2;
		const char*	lvs;
		//read verb level from environment
		lvs=get_env("verb",envp);
		sscanf(lvs,"%d",&lv2);
		//skip if verb suppressed
		if(lv>lv2)	return;
		fprintf(fp,"%s PLUGIN %s: ",get_localtime(),plugin_name);
		vfprintf(fp,format,arglist);
	}
	inline void log(FILE* fp,int lv,const char *envp[],const char format[],...)
	{
		va_list arglist;
		va_start(arglist,format);
		log(stderr,lv,envp,format,arglist);
		va_end(arglist);
	}
	inline void log(int lv,const char *envp[],const char format[],va_list arglist)
	{
		log(stderr,lv,envp,format,arglist);
	}
	inline void log(int lv,const char *envp[],const char format[],...)
	{
		va_list arglist;
		va_start(arglist,format);
		log(lv,envp,format,arglist);
		va_end(arglist);
	}
	static const char *get_env(const char *name, const char *envp[])
	{
		//get environmental variable as char*
	  if (envp)
		{
		  int i;
		  const int namelen = strlen (name);
		  for (i = 0; envp[i]; ++i)
		{
		  if (!strncmp (envp[i], name, namelen))
			{
			  const char *cp = envp[i] + namelen;
			  if (*cp == '=')
			return cp + 1;
			}
		}
		}
	  return NULL;
	}
public:
#define LOGERROR(MSG...)	log(0,envp,MSG)
#define	LOGWARN(MSG...)		log(1,envp,MSG)
#define	LOGINFO(MSG...)		log(3,envp,MSG)
#define	LOGDEBUG(MSG...)	log(10,envp,MSG)
#define ERRET(RET,MSG...)	{LOGERROR("Error at file: %s, line: %u: ",__FILE__,__LINE__);\
	LOGERROR(MSG);LOGERROR(ENDL);return RET;}		//print error MSG... to stderr, and return with value RET
	plugin_base()
	{
		plugin_name="base";
	}
	plugin_base(int *ret,unsigned int *type_mask,const char *argv[], const char *envp[],struct openvpn_plugin_string_list **return_list)
	{
		*ret=1;
		ERRET(,"Not Implemented.");
	}
};

class PCLASS : protected plugin_base
{
private:
	char	*opt_fout_stat;				//aggregated usage output statistics file name
	unsigned int proc_args(const char *argv[],const char *envp[])
	{
		//processes plugin arguments, returns the mask needed
		unsigned int mask=0;
		int argc=0;
		const char** p=argv;
		int c,t;
		//initial values
		opt_fout_stat=0;
		//count argc
		while(*p)
		{
			p++;
			argc++;
		}
		//process args
		while((c=getopt(argc,(char* const*)argv,"s:"))!=-1)
		{
			switch(c)
			{
			case 's':
				t=strlen(optarg);
				opt_fout_stat=(char*)calloc(t+1,sizeof(char));
				if(!opt_fout_stat)
				{
					LOGERROR("Not enough memory. -%c option failed.%s", optopt,ENDL);
					break;
				}
				memcpy(opt_fout_stat,optarg,t*sizeof(char));
				mask|=OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
				break;
			case ':':
				LOGERROR("Option -%c requires an operand.%s", optopt,ENDL);
				break;
			case '?':
				LOGERROR("Unrecognized option: '-%c'.%s", optopt,ENDL);
			}
		}
		return mask;
	}
	const char*	audit_format(const char *envp[])
	{
		/*constructs output line as string from envp
		format:	common name,external address:port,internal address,time start,time end,bytes in,bytes out
		*/
#define MAXLEN	512
		const char *name,*addre,*porte,*addri,*tstart0,*tlen0,*bin,*bout;
		char	*time0,tstart[50],*tend;
		static char ans[MAXLEN];
		time_t		rawtime,dtime;
		size_t		sz;
		size_t		len=0;
		memset(ans,0,MAXLEN*sizeof(char));
		name=get_env("common_name",envp);
		addre=get_env("untrusted_ip",envp);
		porte=get_env("untrusted_port",envp);
		addri=get_env("ifconfig_pool_remote_ip",envp);
		tstart0=get_env("time_unix",envp);
		tlen0=get_env("time_duration",envp);
		bin=get_env("bytes_received",envp);
		bout=get_env("bytes_sent",envp);
		sscanf(tstart0,"%ld",&rawtime);
		time0=(char*)get_localtime(rawtime);
		sz=strlen(time0)+1;
		sz*=sizeof(char);
		memcpy(tstart,time0,sz);
		sscanf(tlen0,"%ld",&dtime);
		rawtime+=dtime;
		time0=(char*)get_localtime(rawtime);
		sz=strlen(time0)+1;
		tend=time0;
		len=strlen(name)+strlen(addre);
		len+=strlen(porte)+strlen(addri);
		len+=strlen(tstart)+strlen(tend)+strlen(bin)+strlen(bout)+9;
		if(len>=MAXLEN)
		{
			ans[0]=0;
			ERRET(0,"Line width (%d) exceeds maximum (%d).%s",len,MAXLEN,ENDL);
		}	
		sprintf(ans,"%s,%s:%s,%s,%s,%s,%s,%s%s",name,addre,porte,addri,tstart,tend,bin,bout,ENDL);
		return ans;
#undef MAXLEN
	}
	int	p_client_disconnect(const char *argv[], const char *envp[])
	{
		//message handler for client disconnect
		char		*name;				//strings
		const char	*s1;
		FILE		*fp=0;
		if(opt_fout_stat)
		{
			fp=fopen(opt_fout_stat,"a");
			if(!fp)
				ERRET(OPENVPN_PLUGIN_FUNC_ERROR,"Can't open stat output file: %s",opt_fout_stat);
			s1=audit_format(envp);
			if(!s1)
			{
				fclose(fp);
				return OPENVPN_PLUGIN_FUNC_ERROR;
			}
			fprintf(fp,"%s",s1);
			fclose(fp);
			name=(char*)get_env("common_name",envp);
			LOGINFO("Client \"%s\" disconnected and audited.%s",name,ENDL);
		}
		return OPENVPN_PLUGIN_FUNC_SUCCESS;
	}
public:
	PCLASS(int *ret,unsigned int *type_mask,const char *argv[], const char *envp[],struct openvpn_plugin_string_list **return_list)
	{
		plugin_name=PLUGIN_NAME;
		*ret=1;
		unsigned int mask;
		mask=proc_args(argv,envp);
		//first check mask support
		if((*type_mask&mask)!=mask)
			LOGERROR("OpenVPN does not support full functionality in the mask. Requested: %X. Supported: %X.",mask,*type_mask);
		*type_mask=mask;
		LOGINFO("Initialization completed.%s",ENDL);
		*ret=0;
	}
	~PCLASS(){
		if(opt_fout_stat)
			free(opt_fout_stat);
		opt_fout_stat=0;
	}
	int p(const int type, const char *argv[], const char *envp[])
	{
		//message splitter
		if(type==OPENVPN_PLUGIN_CLIENT_DISCONNECT)
			return p_client_disconnect(argv,envp);
		else
			return OPENVPN_PLUGIN_FUNC_ERROR;
	}
#undef LOGERROR
#undef LOGWARN
#undef LOGINFO
#undef LOGDEBUG
#undef ERRET
};

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2 (unsigned int *type_mask,const char *argv[], const char *envp[],struct openvpn_plugin_string_list **return_list)
{
	//Initialization
	PCLASS *a;
	int	ret;
	ret=0;
	a=new PCLASS(&ret,type_mask,argv,envp,return_list);
	if(a&&!ret)
		return a;
	return 0;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
	//event processing handle
	if(!handle)	return OPENVPN_PLUGIN_FUNC_ERROR;
	PCLASS *p=(PCLASS*)handle;
	return p->p(type,argv,envp);
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
	//clean up
	if(!handle)	return;
	PCLASS	*p=(PCLASS*)handle;
	delete p;
}

