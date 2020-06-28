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

#include <stdio.h>
#include <time.h>
#include "rainbow_table.h"
#include "md5.h"

/*****************************************************************************/
/* Global Variables                                                          */
/*****************************************************************************/

unsigned int g_u4_rb_tbl[MAX_ROWS_RB_TABLE][MAX_COLS_RB_TABLE] = {{0},};

unsigned char g_u1_digit_sym_ascii[10]    = {0x30, 0x31, 0x32, 0x33, 0x34,
										     0x35, 0x36, 0x37, 0x38, 0x39};

unsigned char g_u1_lwr_char_sym_ascii[26] = {0x61, 0x62, 0x63, 0x64, 0x65,
										     0x66, 0x67, 0x68, 0x69, 0x6A,
										     0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
										     0x70, 0x71, 0x72, 0x73, 0x74,
										     0x75, 0x76, 0x77, 0x78, 0x79,
										     0x7A};


unsigned char g_u1_upr_char_sym_ascii[26] = {0x41, 0x42, 0x43, 0x44, 0x45,
										     0x46, 0x47, 0x48, 0x49, 0x4A,
										     0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
										     0x50, 0x51, 0x52, 0x53, 0x54,
										     0x55, 0x56, 0x57, 0x58, 0x59,
										     0x5A};
/* Needed to compute MD5 */
MD5_CTX mdContext = {{0},};


/*****************************************************************************/
/* Function Definitions                                                      */
/*****************************************************************************/

/*****************************************************************************/
/* This function carries out reduction of a hash and produces a 4 byte output*/
/* that maps into the password space.                                        */
/*****************************************************************************/

unsigned int reduction_fn(unsigned int u4_hash)
{
	unsigned int  u4_i       = 0;
	unsigned char u1_byte[4] = {0};
	unsigned int  u4_pswd    = 0;

	/* Extract bytes from the hash */
	u1_byte[0] = (unsigned char)(u4_hash  & 0x000000FF);
	u1_byte[1] = (unsigned char)((u4_hash & 0x0000FF00) >> 8);
	u1_byte[2] = (unsigned char)((u4_hash & 0x00FF0000) >> 16);
	u1_byte[3] = (unsigned char)((u4_hash & 0xFF000000) >> 24);

	for(u4_i = 0; u4_i < 4; u4_i++)
	{
		unsigned int u4_bin = u1_byte[u4_i] % 3 + 1;

		switch(u4_bin)
		{
			case 1:
			{
				unsigned char u1_sym_to_pick = u1_byte[u4_i] % 10;

				if(u4_i == 0)
					u4_pswd |= (unsigned int) g_u1_digit_sym_ascii[u1_sym_to_pick];
				else if(u4_i == 1)
					u4_pswd |= (unsigned int) (g_u1_digit_sym_ascii[u1_sym_to_pick] << 8);
				else if(u4_i == 2)
					u4_pswd |= (unsigned int) (g_u1_digit_sym_ascii[u1_sym_to_pick] << 16);
				else
					u4_pswd |= (unsigned int) (g_u1_digit_sym_ascii[u1_sym_to_pick] << 24);
			}
			break;

			case 2:
			{
				unsigned char u1_sym_to_pick = u1_byte[u4_i] % 26;

				if(u4_i == 0)
					u4_pswd |= (unsigned int) g_u1_lwr_char_sym_ascii[u1_sym_to_pick];
				else if(u4_i == 1)
					u4_pswd |= (unsigned int) (g_u1_lwr_char_sym_ascii[u1_sym_to_pick] << 8);
				else if(u4_i == 2)
					u4_pswd |= (unsigned int) (g_u1_lwr_char_sym_ascii[u1_sym_to_pick] << 16);
				else
					u4_pswd |= (unsigned int) (g_u1_lwr_char_sym_ascii[u1_sym_to_pick] << 24);
			}
			break;

			case 3:
			{
				unsigned char u1_sym_to_pick = u1_byte[u4_i] % 26;

				if(u4_i == 0)
					u4_pswd |= (unsigned int) g_u1_upr_char_sym_ascii[u1_sym_to_pick];
				else if(u4_i == 1)
					u4_pswd |= (unsigned int) (g_u1_upr_char_sym_ascii[u1_sym_to_pick] << 8);
				else if(u4_i == 2)
					u4_pswd |= (unsigned int) (g_u1_upr_char_sym_ascii[u1_sym_to_pick] << 16);
				else
					u4_pswd |= (unsigned int) (g_u1_upr_char_sym_ascii[u1_sym_to_pick] << 24);
			}
			break;

			default: /* Do nothing */
			break;
		}
	}

	return u4_pswd;
}

/*****************************************************************************/
/* This function computes the hash given a password by using MD5 internally. */
/*****************************************************************************/

unsigned int hash_fn(unsigned int u4_paswd)
{
	unsigned int u4_hash   = 0;
	unsigned int *pu4_temp = NULL;

	MD5Init(&mdContext);
	MD5Update(&mdContext, &u4_paswd, 4);
	MD5Final(&mdContext);
	pu4_temp = (unsigned int *) &mdContext.digest[12];

	u4_hash = *pu4_temp;

	return u4_hash;
}

/*****************************************************************************/
/* This function checks if the given byte of password matches the password   */
/* characteristics.                                                          */
/*****************************************************************************/

unsigned int check_pw(unsigned char pass_byte)
{
	unsigned int result1 = 0;

	if (!(((pass_byte >= 0x30) && (pass_byte <= 0x39)) ||
		  ((pass_byte >= 0x41) && (pass_byte <= 0x5A)) ||
	      ((pass_byte >= 0x61) && (pass_byte <= 0x7A))))
	{
		result1 = 1;
	}

	return result1;
}

/*****************************************************************************/
/* This function computes all possible passwords and stores them in the      */
/* rainbow table.                                                            */
/*****************************************************************************/

void create_rb_tbl_pswds()
{
	unsigned int u4_passwd            = 0x30303030;
	unsigned int u4_found_paswds      = 0;
	unsigned int u4_found_rb_tbl_pswd = 0;

	while(u4_passwd <= 0x7a7a7a7a)
	{
		unsigned int  u4_check        = 0;
		unsigned int  u4_check_passwd = 0;
		unsigned int  u4_i            = 0;
		unsigned char u1_pass_byte[4] = {0};

		u1_pass_byte[0] = (unsigned char)(u4_passwd & 0xFF);
		u1_pass_byte[1] = (unsigned char)((u4_passwd & 0xFF00) >> 8);
		u1_pass_byte[2] = (unsigned char)((u4_passwd & 0xFF0000) >> 16);
		u1_pass_byte[3] = (unsigned char)((u4_passwd & 0xFF000000) >> 24);


		for(u4_i = 0; u4_i < 4; u4_i++)
		{
			u4_check_passwd = check_pw(u1_pass_byte[u4_i]);

			if(u4_check_passwd == 1)
				break;

			u4_check++;
		}

		if (u4_check == 4)
		{
			if((u4_found_paswds % MAX_HASH_CAHINS) == 0)
			{
				if(u4_found_rb_tbl_pswd < MAX_ROWS_RB_TABLE)
				{
					/* Populate the first column of the RB Table with passwords */
					g_u4_rb_tbl[u4_found_rb_tbl_pswd][0] = u4_passwd;
					u4_found_rb_tbl_pswd++;
				}
			}

			u4_found_paswds++;
		}

		u4_passwd++;
	}
}

/*****************************************************************************/
/* This function populates the reduced hashes in the rainbow table by        */
/* computing the hash chain.                                                 */
/*****************************************************************************/

void create_rb_tbl_hashs()
{
	unsigned int u4_i = 0;
	unsigned int u4_j = 0;

	for(u4_i = 0; u4_i < MAX_ROWS_RB_TABLE; u4_i++)
	{
		unsigned int u4_temp_hash_red_input = g_u4_rb_tbl[u4_i][0];

		for(u4_j = 0; u4_j < MAX_HASH_CHAINS_COL_CORRECTION; u4_j++)
		{
			u4_temp_hash_red_input = hash_fn(u4_temp_hash_red_input);
			u4_temp_hash_red_input = reduction_fn(u4_temp_hash_red_input);
		}

		g_u4_rb_tbl[u4_i][1] = u4_temp_hash_red_input;
	}
}

/*****************************************************************************/
/* This function populates the rainbow table by creating possible passwords  */
/* and reduced hashes from the hash chain.                                   */
/*****************************************************************************/

void create_rb_tbl()
{
	int u4_i = 0;

	create_rb_tbl_pswds();

	for(u4_i = 0; u4_i < MAX_ROWS_RB_TABLE; u4_i++)
	{
		if(g_u4_rb_tbl[u4_i][0] == 0)
		{
			printf("RB TBL init error - row number %d\n", u4_i);
		}
	}

	create_rb_tbl_hashs();

}

/*****************************************************************************/
/* This function prints the rainbow table stored as a global.                */
/*****************************************************************************/

void print_rb_tbl()
{
	unsigned int u4_i = 0;

	printf("Password, Hash\n");

	for(u4_i = 0; u4_i < MAX_ROWS_RB_TABLE; u4_i++)
	{
		printf("0x%.08x, 0x%.8x, ", g_u4_rb_tbl[u4_i][0], g_u4_rb_tbl[u4_i][1]);

		if((((u4_i + 1) % 4) == 0))
			printf("\n");
	}

}

/*****************************************************************************/
/* This is the entry point to the program. It creates the rainbow table.     */
/* Then prints it out to console.                                            */
/*****************************************************************************/

int main()
{
	time_t start_time = 0;
	time_t end_time   = 0;

	start_time = time(NULL);

	create_rb_tbl();

	end_time = time(NULL);

	printf("Time taken to create rb_tbl: %ds\n", (int)(end_time - start_time));

	print_rb_tbl();
	return 0;
}




