/* This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more 
 * details.
 *
 * You should have received a copy of the GNU General Public License version 2
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (c) 2014 Philip Tricca <flihp@twobit.us>
 */

#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*  Program to output (pseudo) random bytes from the OpenSSL RAND API.
 *  RAND is seeded from a persistent seed file or /dev/random if seed
 *  file isn't present.
 */
#define SEED_FILE "/var/lib/rand/rand.seed"
#define ENTROPY_SOURCE "/dev/random"
#define ENTROPY_SIZE 32
#define USAGE fprintf (stderr, "Usage: %s [--hex|--verbose|--help] bytes\n", argv [0]);
#define MAX_BYTES 1024

typedef struct {
    bool hex;
    bool verbose;
    size_t bytes;
} args_t;

/* Global structure representing command line arguments.
 * This is populated in args_parse and NEVER MODIFIED AGAIN.
 */
args_t args = { 0, };

/*  Seed the OpenSSL RAND state.
 *
 *  Check for existance of seed file and use it if possible.
 *  If no seed file, fall back to reading from ENTROPY_SOURCE.
 *  Special cases:
 *  1: Don't use a read only seed file as this program won't be able to dump
 *     state to it when it's done. This cause the randomness of the next run
 *     to be decreased.
 *  2: Don't use a seed file that's too small (less than ENTROPY_SIZE).
 *  3: Don't use a seed file that's not a file (except for ENTROPY_SOURCE).
 */
static int
seed_rand (const char* seed_file)
{
    struct stat seed_stat = { 0, };
    unsigned long randerr = 0;
    const char* seed = seed_file;
    int size = ENTROPY_SIZE;

    if (access (seed_file, R_OK | W_OK) == 0) {
        if (lstat (seed_file, &seed_stat) == -1) {
            perror ("Error executing lstat on seed file: ");
            goto err_out;
        }
        if (!S_ISREG (seed_stat.st_mode)) {
            /* seed file isn't a regular file:
               try to remove it if possible and fall back to ENTROPY_SOURCE
             */
            seed = ENTROPY_SOURCE;
            fprintf (stderr,
                     "Seed file isn't regular file: %s. Falling back to %s\n",
                     seed_file, ENTROPY_SOURCE);
            if (unlink (seed_file) == -1) {
                perror ("Error executing unlink on seed file: ");
            }
        }
        if (seed_stat.st_size < ENTROPY_SIZE) {
            /* seed file isn't at least ENTROPY_SIZE bytes */
            seed = ENTROPY_SOURCE;
            fprintf (stderr,
                     "Seed file is too samll. Falling back to %s.\n", seed);
            if (unlink (seed_file) == -1) {
                perror ("Error executing unlink on seed file: ");
            }
        } else { /* use size from seed file */
            size = seed_stat.st_size;
        }
    } else {
        seed = ENTROPY_SOURCE;
        fprintf (stderr,
                 "Unable to access seed file. If it exists, be sure it's "
                 "both readable and writable. Falling back to %s.\n",
                 ENTROPY_SOURCE);
    }

    if (RAND_load_file (seed, size) != size) {
        randerr = ERR_get_error ();
        fprintf (stderr, "RAND_load_file failed: %s\n", ERR_reason_error_string (randerr));
        goto err_out;
    } else if (args.verbose) {
        fprintf (stderr, "RAND_load_file: loaded %d bytes from %s\n", size, seed);
    }
    return 0;
err_out:
    return 1;
}

static int
seed_save (const char* seed_file)
{
    int bytes = 0;
    unsigned long randerr = 0;
    char* dirend = NULL;
    char dirpart [PATH_MAX] = { 0, };
    DIR* dir = NULL;

    /* be sure parent directory exists */
    dirend = strrchr (seed_file, '/');
    strncpy (dirpart, seed_file, dirend - seed_file);
    dir = opendir (dirpart);
    if (!dir) {
        if (errno == ENOENT) {
            if (mkdir (dirpart, S_IRWXU | S_IRGRP | S_IXGRP) == -1) {
                fprintf (stderr, "Error executing mkdir %s: ", dirpart);
                perror (NULL);
            }
        } else {
            fprintf (stderr, "Error executing opendir on %s: ", dirpart);
            perror (NULL);
        }
    } else {
        closedir (dir);
    }
    /* persist RAND state */
    bytes = RAND_write_file (seed_file);
    if (bytes == -1) {
        randerr = ERR_get_error ();
        fprintf (stderr, "RAND_write_file failed: %s\n", ERR_reason_error_string (randerr));
        return 1;
    } else if (args.verbose) {
        fprintf (stderr, "RAND_write_file wrote %d bytes to %s\n", bytes, seed_file);
    }
    return 0;
}

static char*
get_rand (unsigned char* dest, size_t size)
{
    unsigned long randerr = 0;
    if (args.verbose)
        fprintf (stderr, "reading %d RAND_bytes\n", size);
    if (RAND_bytes (dest, size) != 1) {
        randerr = ERR_get_error ();
        fprintf (stderr,
                 "RAND_bytes failed: %s\n",
                 ERR_reason_error_string (randerr));
        return NULL;
    }
    return dest;
}

static void
args_parse (int argc, char* argv[])
{
    int ret = 0, i = 0;
    static struct option options[] = {
        {     "hex",    no_argument, NULL, 'x' },
        { "verbose",    no_argument, NULL, 'v' },
        {    "help",    no_argument, NULL, 'h' },
        {      NULL,              0, NULL,  0  }
    };
    while ((ret = getopt_long(argc, argv, ":xv", options, NULL)) != -1) {
        switch (ret) {
        case 'x':
            args.hex = true;
            break;
        case 'v':
            args.verbose = true;
            break;
        case 'h':
        case '?':
            USAGE;
            exit (EXIT_SUCCESS);
            break;
        default:
            fprintf (stderr, "Unexpected argument: %c", ret);
            break;
        }
    }
    if (argc != (optind + 1)) {
        USAGE;
        exit (EXIT_FAILURE);
    }
    args.bytes = strtol (argv[optind], NULL, 10);
}

/*  Return 1 for any failures.
 */
static int
args_sanity ()
{
    if (args.bytes == LONG_MIN ||
        args.bytes == LONG_MAX ||
        args.bytes > MAX_BYTES ||
        args.bytes <= 0)
    {
        fprintf (stderr, "\'bytes\' must be between 0 and %d\n", MAX_BYTES);
        return 1;
    }
    return 0;
}

int
main (int argc, char* argv[])
{
    int success = EXIT_SUCCESS;
    int i;
    unsigned long randerr = 0;
    unsigned char buffer [MAX_BYTES];

    args_parse (argc, argv);
    if (args_sanity ())
        exit (EXIT_FAILURE);

    if (seed_rand (SEED_FILE))
        exit (EXIT_FAILURE);

    if (get_rand (buffer, args.bytes) == NULL)
        exit (EXIT_FAILURE);

    for (i = 0; i < args.bytes; ++i) {
        if (args.hex)
            printf ("%02x", buffer [i]);
        else
            printf ("%c", buffer [i]);
    }
    if (args.hex)
        printf ("\n");

    seed_save (SEED_FILE);
    exit (EXIT_SUCCESS);
}
