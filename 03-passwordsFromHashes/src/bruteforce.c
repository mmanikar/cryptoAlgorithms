/*****************************************************************************/
/*                                                                           */
/* Author 1 : Mukund Manikarnike											 */
/* ASU ID   : 1208597425													 */
/* e-mail   : mmanikar@asu.edu; mukunm@gmail.com						     */
/*                                                                           */
/* Author 2 : Lakshmi Srinivas                                               */
/* ASU ID   : 1208635554                                                     */
/* e-mail   : lsriniv2@asu.edu; laksh91@gmail.com							 */
/*                                                                           */
/* Course    : CSE 539                                                       */
/* Instructor: Partha Dasgupta                                               */
/* Semester  : Spring - 2015                                                 */
/* 																			 */
/*****************************************************************************/

/*****************************************************************************/
/* File Includes                                                             */
/*****************************************************************************/

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "md5.h"

/*****************************************************************************/
/* Function Definitions                                                      */
/*****************************************************************************/

/*****************************************************************************/
/* This function checks if the given byte of password matches the password   */
/* characteristics.                                                          */
/*****************************************************************************/

int check_pw(unsigned char pass_byte)
{
	int result1 = 0;

	if (!(((pass_byte >= 0x30) && (pass_byte <= 0x39)) ||
		  ((pass_byte >= 0x41) && (pass_byte <= 0x5A)) ||
	      ((pass_byte >= 0x61) && (pass_byte <= 0x7A))))
	{
		result1 = 1;
	};

	return result1;
}

/*****************************************************************************/
/* This is the entry point to the program. It loops through finding all      */
/* possible passwords, hashing them and comparing them with the provided     */
/* hashes.                                                                   */
/*****************************************************************************/

int main()
{
	time_t start_time = 0;
	time_t end_time   = 0;
	int  found_paswds = 0;
	int  passwd       = 0x30303030;

	start_time = time(NULL);

	while(passwd <= 0x7a7a7a7a)
	{
		int  check        = 0;
		int  *temp        = NULL;
		int  result       = 0;
		int  check_passwd = 0;
		int  i            = 0;
		unsigned char pass_byte[4] = {0};
		MD5_CTX mdContext = {0};  // needed to compute MD5

		pass_byte[0] = (unsigned char)(passwd & 0xFF);
		pass_byte[1] = (unsigned char)((passwd & 0xFF00) >> 8);
		pass_byte[2] = (unsigned char)((passwd & 0xFF0000) >> 16);
		pass_byte[3] = (unsigned char)((passwd & 0xFF000000) >> 24);


		for (i = 0; i < 4; i++)
		{
			check_passwd = check_pw(pass_byte[i]);

			if (check_passwd == 1)
				break;

			check++;
		}

		if(check == 4)
		{
			/* Compute MD5 of password */
			MD5Init(&mdContext);
			MD5Update(&mdContext, &passwd, 4);
			MD5Final(&mdContext);
			temp = (int *) &mdContext.digest[12];

			result = *temp;

			/* Check if the result matches one of the hashes provided */
			if (result == 0x19fbc7c1 || result == 0x7e1d96fd ||
			    result == 0x88df723c || result == 0x3974cffc ||
			    result == 0x8f6bb61b || result == 0x8e564270 ||
			    result == 0x655ca818 || result == 0x58712b2b ||
			    result == 0x97e75d32 || result == 0x14928501 )
			{
				printf("Hash - 0x%x Password - 0x%x\n", result, passwd);
				found_paswds++;
			}

			if(found_paswds == 10)
				break;
		}

		passwd++;
	}

	end_time = time(NULL);

	printf("Time taken to find passwords: %ds\n", (end_time - start_time));

	return 0;
}
