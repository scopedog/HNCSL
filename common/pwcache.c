#if defined(__linux__)

/* $NetBSD: user_from_uid.c,v 1.4 2008/09/21 16:35:25 lukem Exp $ */
/* from NetBSD: pwcache.c,v 1.15 2000/09/13 22:32:28 msaitoh Exp */
/* from	NetBSD: pwcache.h,v 1.2 2000/06/03 13:21:14 simonb Exp */

/*-
 * Copyright (c) 1992 Keith Muller.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Keith Muller of the University of California, San Diego.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "pwcache.h"

/*
 * routines that control user, group, uid and gid caches (for the archive
 * member print routine).
 * IMPORTANT:
 * these routines cache BOTH hits and misses, a major performance improvement
 */

static	int pwopn = 0;		/* is password file open */
static	int gropn = 0;		/* is group file open */
static UIDC **uidtb = NULL;	/* uid to name cache */
static GIDC **gidtb = NULL;	/* gid to name cache */
static UIDC **usrtb = NULL;	/* user name to uid cache */
static GIDC **grptb = NULL;	/* group name to gid cache */

static unsigned int st_hash(const char *, size_t, int);
static int uidtb_start(void);
static int gidtb_start(void);
static int usrtb_start(void);
static int grptb_start(void);

static unsigned int
st_hash(const char *name, size_t len, int tabsz)
{
	unsigned int key = 0;

	while (len--) {
		key += *name++;
		key = (key << 8) | (key >> 24);
	}

	return (key % tabsz);
}

/*
 * uidtb_start
 *	creates an an empty uidtb
 * Return:
 *	0 if ok, -1 otherwise
 */

static int
uidtb_start(void)
{
	static int fail = 0;

	if (uidtb != NULL)
		return (0);
	if (fail)
		return (-1);
	if ((uidtb = (UIDC **)calloc(UID_SZ, sizeof(UIDC *))) == NULL) {
		++fail;
		return (-1);
	}
	return (0);
}

/*
 * gidtb_start
 *	creates an an empty gidtb
 * Return:
 *	0 if ok, -1 otherwise
 */

int
gidtb_start(void)
{
	static int fail = 0;

	if (gidtb != NULL)
		return (0);
	if (fail)
		return (-1);
	if ((gidtb = (GIDC **)calloc(GID_SZ, sizeof(GIDC *))) == NULL) {
		++fail;
		return (-1);
	}
	return (0);
}

/*
 * usrtb_start
 *	creates an an empty usrtb
 * Return:
 *	0 if ok, -1 otherwise
 */

int
usrtb_start(void)
{
	static int fail = 0;

	if (usrtb != NULL)
		return (0);
	if (fail)
		return (-1);
	if ((usrtb = (UIDC **)calloc(UNM_SZ, sizeof(UIDC *))) == NULL) {
		++fail;
		return (-1);
	}
	return (0);
}

/*
 * grptb_start
 *	creates an an empty grptb
 * Return:
 *	0 if ok, -1 otherwise
 */

int
grptb_start(void)
{
	static int fail = 0;

	if (grptb != NULL)
		return (0);
	if (fail)
		return (-1);
	if ((grptb = (GIDC **)calloc(GNM_SZ, sizeof(GIDC *))) == NULL) {
		++fail;
		return (-1);
	}
	return (0);
}

/*
 * user_from_uid()
 *	caches the name (if any) for the uid. If noname clear, we always return the
 *	the stored name (if valid or invalid match). We use a simple hash table.
 * Return
 *	Pointer to stored name (or a empty string)
 */

const char *
user_from_uid(uid_t uid, int noname)
{
	struct passwd *pw;
	UIDC *ptr, **pptr;

	if ((uidtb == NULL) && (uidtb_start() < 0))
		return (NULL);

	/*
	 * see if we have this uid cached
	 */
	pptr = uidtb + (uid % UID_SZ);
	ptr = *pptr;

	if ((ptr != NULL) && (ptr->valid > 0) && (ptr->uid == uid)) {
		/*
		 * have an entry for this uid
		 */
		if (!noname || (ptr->valid == VALID))
			return (ptr->name);
		return (NULL);
	}

	/*
	 * No entry for this uid, we will add it
	 */
	if (!pwopn) {
		++pwopn;
	}

	if (ptr == NULL)
		*pptr = ptr = (UIDC *)malloc(sizeof(UIDC));

	if ((pw = getpwuid(uid)) == NULL) {
		/*
		 * no match for this uid in the local password file
		 * a string that is the uid in numberic format
		 */
		if (ptr == NULL)
			return (NULL);
		ptr->uid = uid;
#		ifdef NET2_STAT
		(void)snprintf(ptr->name, UNMLEN, "%u", uid);
#		else
		(void)snprintf(ptr->name, UNMLEN, "%lu", (long) uid);
#		endif
		ptr->valid = INVALID;
		if (noname)
			return (NULL);
	} else {
		/*
		 * there is an entry for this uid in the password file
		 */
		if (ptr == NULL)
			return (pw->pw_name);
		ptr->uid = uid;
		(void)strncpy(ptr->name, pw->pw_name, UNMLEN);
		ptr->name[UNMLEN-1] = '\0';
		ptr->valid = VALID;
	}
	return (ptr->name);
}

/*
 * group_from_gid()
 *	caches the name (if any) for the gid. If noname clear, we always return the
 *	the stored name (if valid or invalid match). We use a simple hash table.
 * Return
 *	Pointer to stored name (or a empty string)
 */

const char *
group_from_gid(gid_t gid, int noname)
{
	struct group *gr;
	GIDC *ptr, **pptr;

	if ((gidtb == NULL) && (gidtb_start() < 0))
		return (NULL);

	/*
	 * see if we have this gid cached
	 */
	pptr = gidtb + (gid % GID_SZ);
	ptr = *pptr;

	if ((ptr != NULL) && (ptr->valid > 0) && (ptr->gid == gid)) {
		/*
		 * have an entry for this gid
		 */
		if (!noname || (ptr->valid == VALID))
			return (ptr->name);
		return (NULL);
	}

	/*
	 * No entry for this gid, we will add it
	 */
	if (!gropn) {
		++gropn;
	}

	if (ptr == NULL)
		*pptr = ptr = (GIDC *)malloc(sizeof(GIDC));

	if ((gr = getgrgid(gid)) == NULL) {
		/*
		 * no match for this gid in the local group file, put in
		 * a string that is the gid in numberic format
		 */
		if (ptr == NULL)
			return (NULL);
		ptr->gid = gid;
#		ifdef NET2_STAT
		(void)snprintf(ptr->name, GNMLEN, "%u", gid);
#		else
		(void)snprintf(ptr->name, GNMLEN, "%lu", (long) gid);
#		endif
		ptr->valid = INVALID;
		if (noname)
			return (NULL);
	} else {
		/*
		 * there is an entry for this group in the group file
		 */
		if (ptr == NULL)
			return (gr->gr_name);
		ptr->gid = gid;
		(void)strncpy(ptr->name, gr->gr_name, GNMLEN);
		ptr->name[GNMLEN-1] = '\0';
		ptr->valid = VALID;
	}
	return (ptr->name);
}

/*
 * uid_from_user()
 *	caches the uid for a given user name. We use a simple hash table.
 * Return
 *	the uid (if any) for a user name, or a -1 if no match can be found
 */

int
uid_from_user(const char *name, uid_t *uid)
{
	struct passwd *pw;
	UIDC *ptr, **pptr;
	size_t namelen;

	/*
	 * return -1 for mangled names
	 */
	if (name == NULL || ((namelen = strlen(name)) == 0))
		return (-1);
	if ((usrtb == NULL) && (usrtb_start() < 0))
		return (-1);

	/*
	 * look up in hash table, if found and valid return the uid,
	 * if found and invalid, return a -1
	 */
	pptr = usrtb + st_hash(name, namelen, UNM_SZ);
	ptr = *pptr;

	if ((ptr != NULL) && (ptr->valid > 0) && !strcmp(name, ptr->name)) {
		if (ptr->valid == INVALID)
			return (-1);
		*uid = ptr->uid;
		return (0);
	}

	if (!pwopn) {
		++pwopn;
	}

	if (ptr == NULL)
		*pptr = ptr = (UIDC *)malloc(sizeof(UIDC));

	/*
	 * no match, look it up, if no match store it as an invalid entry,
	 * or store the matching uid
	 */
	if (ptr == NULL) {
		if ((pw = getpwnam(name)) == NULL)
			return (-1);
		*uid = pw->pw_uid;
		return (0);
	}
	(void)strncpy(ptr->name, name, UNMLEN);
	ptr->name[UNMLEN-1] = '\0';
	if ((pw = getpwnam(name)) == NULL) {
		ptr->valid = INVALID;
		return (-1);
	}
	ptr->valid = VALID;
	*uid = ptr->uid = pw->pw_uid;
	return (0);
}

/*
 * gid_from_group()
 *	caches the gid for a given group name. We use a simple hash table.
 * Return
 *	the gid (if any) for a group name, or a -1 if no match can be found
 */

int
gid_from_group(const char *name, gid_t *gid)
{
	struct group *gr;
	GIDC *ptr, **pptr;
	size_t namelen;

	/*
	 * return -1 for mangled names
	 */
	if (name == NULL || ((namelen = strlen(name)) == 0))
		return (-1);
	if ((grptb == NULL) && (grptb_start() < 0))
		return (-1);

	/*
	 * look up in hash table, if found and valid return the uid,
	 * if found and invalid, return a -1
	 */
	pptr = grptb + st_hash(name, namelen, GID_SZ);
	ptr = *pptr;

	if ((ptr != NULL) && (ptr->valid > 0) && !strcmp(name, ptr->name)) {
		if (ptr->valid == INVALID)
			return (-1);
		*gid = ptr->gid;
		return (0);
	}

	if (!gropn) {
		++gropn;
	}

	if (ptr == NULL)
		*pptr = ptr = (GIDC *)malloc(sizeof(GIDC));

	/*
	 * no match, look it up, if no match store it as an invalid entry,
	 * or store the matching gid
	 */
	if (ptr == NULL) {
		if ((gr = getgrnam(name)) == NULL)
			return (-1);
		*gid = gr->gr_gid;
		return (0);
	}

	(void)strncpy(ptr->name, name, GNMLEN);
	ptr->name[GNMLEN-1] = '\0';
	if ((gr = getgrnam(name)) == NULL) {
		ptr->valid = INVALID;
		return (-1);
	}
	ptr->valid = VALID;
	*gid = ptr->gid = gr->gr_gid;
	return (0);
}

#endif // defined(__linux__)
