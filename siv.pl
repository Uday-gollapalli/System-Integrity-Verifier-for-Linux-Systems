#!/usr/bin/env perl

use strict;
use warnings;

use v5.10;

my %opts;

use Data::Dumper;
use Getopt::Std;
use File::Find;
use Storable;
use Cwd 'abs_path';
use File::Basename;
use File::Spec;

use Digest::SHA;
use Digest::MD5;

my $mode;
my $current_data;

getopts( 'ivhD:V:R:H:', \%opts );

$opts{'i'} = 0 if not exists $opts{'i'};
$opts{'v'} = 0 if not exists $opts{'v'};
$opts{'h'} = 0 if not exists $opts{'h'};

# When the help option (-h) is given, the program will print the accepted command-line arguments with a short explanation for each,
if ( $opts{'h'} ) {
    show_usage();
    exit;
}

my $monitored_directory = $opts{'D'};
my $verification_file   = $opts{'V'};
my $report_file         = $opts{'R'};

unless ($monitored_directory) {
    say "Error: monitored_directory should be specified";
    exit;
}

unless ($verification_file) {
    say "Error: verification_file should be specified";
    exit;
}

unless ($report_file) {
    say "Error: report_file should be specified";
    exit;
}

$monitored_directory = abs_path($monitored_directory);
$verification_file   = abs_path($verification_file);
$report_file         = abs_path($report_file);

if ( is_file_in_dir( $verification_file, $monitored_directory ) ) {
    say "Error: verification file is inside the monitored directory";
    exit;
}

if ( is_file_in_dir( $report_file, $monitored_directory ) ) {
    say "Error: report file is inside the monitored directory";
    exit;
}

my $hash_function;
my $stats = { files_parsed => 0, directories_parsed => 0 };
my @log;

# The options -i (indicating initialization mode), -v (indicating verification mode) ,and –h (indicating help mode) are mutually exclusive.
if ( ( $opts{'i'} + $opts{'v'} + $opts{'h'} ) > 1 ) {
    say
        "Error: The options -i (indicating initialization mode), -v (indicating verification mode) ,and –h (indicating help mode) are mutually exclusive.";
    exit;
}

if ( -f $report_file ) {
    confirm("report file already exists ($report_file). Overwrite the existing file? [yes/no], default no") or exit;
}

# Detect mode

if ( $opts{'i'} ) {
    $mode = 'initialization';

    # a) Verify that the specified monitored directory exists
    unless ( -d $monitored_directory ) {
        say "Error: monitored_directory ($monitored_directory) not exists";
        exit;
    }

    # b) Verify that the specified verification file and the report file are outside the monitored
    # directory

    # c) Verify that the specified hash function is supported by your SIV
    # MD-5 and SHA-1
    unless ( $opts{'H'} ) {
        say "Error: No hash function specified";
        exit;
    }

    $hash_function = $opts{'H'};
    $hash_function =~ s/-//g;
    $hash_function =~ tr/A-Z/a-z/;

    unless ( ( $hash_function eq 'md5' ) || ( $hash_function eq 'sha1' ) ) {
        say "Error: hash function should be MD5 or SHA1";
        exit;
    }

    # d) If the verification file or report file exists already then the user will be asked if he
    # wants to overwrite the existing file. If answer is “no”, the program terminates.

    if ( -f $verification_file ) {
        confirm(
            "verification file already exists ($verification_file). Overwrite the existing file? [yes/no], default no")
            or
            exit;
    }

} elsif ( $opts{'v'} ) {
    $mode = 'verification';

#The options -V and -H are mutually exclusive, meaning that you specify the hash function only when you create the verification file (in initialization mode). In verification mode, the hash function must be recovered from the verification file.

    if ( exists $opts{V} && exists $opts{H} ) {
        say
            "Error: The options -V and -H are mutually exclusive, meaning that you specify the hash function only when you create the verification file (in initialization mode). In verification mode, the hash function must be recovered from the verification file.";
        exit;
    }

} else {
    say "Error: you should specify mode to run. use -h for details";
    exit;
}

$stats->{start_time} = time();

my $data;
if ( $mode eq 'verification' ) {

    # a) Verify that the specified verification file exists and, if true, begin parsing the file
    unless ( -f $verification_file ) {
        say "Error: verification_file ($verification_file) not exists";
        exit;
    }

    $data          = retrieve($verification_file);
    $hash_function = $data->{hash_function};
}

find( \&process, $monitored_directory );

# print Dumper $current_data;

if ( $mode eq 'initialization' ) {

    # store data to file
    store {
        hash_function => $hash_function,
        files         => $current_data
        },
        $verification_file;

    open( F, ">", $report_file );

    print F "Report for initialization mode\n\n";

    # I. Full pathname to monitored directory
    print F "Full pathname to monitored directory:\t" . $monitored_directory . "\n";

    # II. Full pathname to verification file
    print F "Full pathname to verification file:\t" . $verification_file . "\n";

    # III. Full pathname to report file
    print F "Full pathname to report file:\t\t" . $report_file . "\n";

    # IV. Number of directories parsed
    print F "Number of directories parsed:\t\t" . $stats->{directories_parsed} . "\n";

    # V. Number of files parsed
    print F "Number of files parsed:\t\t\t" . $stats->{files_parsed} . "\n";

    # VI. Time to complete the initialization mode
    print F "Time to complete:\t\t\t" . ( time() - $stats->{start_time} ) . " seconds\n";

    close(F)

} else {
    my $verification = $data->{files};

    foreach my $file ( keys %{$current_data} ) {    # loop across all files in important_directory

        if ( not exists $verification->{$file} ) {    # file not exists in verification table - new file!
            if ( -f $file ) {
                push @log, $file . ": new file in monitored directory";
            } else {
                push @log, $file . ": new directory in monitored directory";
            }
        } else {
            $verification->{$file}{seen} = 1;         # mark, that we seen this file

            verify_path( $file, $current_data->{$file}, $verification->{$file} );    # compare records
        }
    }

    foreach my $file ( keys %{$verification} ) {    # loop across all verification table
        if ( not exists $verification->{$file}{seen} ) {    # check if we seen file at previous step
            push @log, $file . ": not exists in monitored directory";
        }
    }

    open( F, ">", $report_file );

    print F "Report for verification mode\n\n";

    # I. Full pathname to monitored directory
    print F "Full pathname to monitored directory:\t" . $monitored_directory . "\n";

    # II. Full pathname to verification file
    print F "Full pathname to verification file:\t" . $verification_file . "\n";

    # III. Full pathname to report file
    print F "Full pathname to report file:\t\t" . $report_file . "\n";

    # IV. Number of directories parsed
    print F "Number of directories parsed:\t\t" . $stats->{directories_parsed} . "\n";

    # V. Number of files parsed
    print F "Number of files parsed:\t\t\t" . $stats->{files_parsed} . "\n";

    # VI. Number of warning issued
    print F "Number of warning issued:\t\t" . scalar(@log) . "\n";
    
    # VII. Time to complete the verification mode
    print F "Time to complete:\t\t\t" . ( time() - $stats->{start_time} ) . " seconds\n";

    print F "\n\n";
    if ( scalar(@log) > 0 ) {
        print F "Warnings:\n\n";
        foreach (@log) {
            print F $_ . "\n";
        }
    } else {
        print F "No warnings\n\n";
    }

    close(F);
}

##########################
# Additional subroutines #
##########################

# Process each, and fill $current_data hash
sub process {

    my $pathname = $File::Find::name;    # I. Full path to file, including pathname

    # do not check "." and ".." directories
    return if $_ eq '.';
    return if $_ eq '..';

    my @stats = stat($pathname);

    my $tmp = {};

    if ( -f $pathname ) {

        # this is file
        $tmp->{type} = 'file';
        $tmp->{size} = $stats[7];    # II. Size of the file
        $tmp->{checksum} =
            get_checksum($pathname);    # VII. Computed message digest with specified hash function over file contents
        $stats->{files_parsed}++;
    } else {
        $tmp->{type} = 'folder';
        $stats->{directories_parsed}++;
    }

    # III. Name of user owning the file
    $tmp->{uid}       = $stats[4];                 # also we storing UID
    $tmp->{user_name} = getpwuid( $tmp->{uid} );

    # IV. Name of group owning the file
    $tmp->{gid}        = $stats[5];                 # Also we storing GID
    $tmp->{group_name} = getgrgid( $tmp->{gid} );

    $tmp->{mode} = sprintf "%04o", $stats[2] & 07777;    # V. Access rights to the file (either octal or symbolic)

    $tmp->{mtime} = $stats[9];                           # VI. Last modification date

    $current_data->{$pathname} = $tmp;
}

# check path
sub verify_path {
    my ( $file, $current, $saved ) = @_;

    # Check size & checksum only for files
    if ( $current->{type} eq 'file' ) {
        if ( $current->{size} != $saved->{size} ) {
            push @log, $file . ": size different";
        }

        if ( $current->{checksum} ne $saved->{checksum} ) {
            push @log, $file . ": checksum different";
        }

    }

    if ( $current->{gid} != $saved->{gid} ) {
        push @log, $file . ": gid different";
    }

    if ( $current->{uid} != $saved->{uid} ) {
        push @log, $file . ": uid different";
    }

    if ( $current->{group_name} ne $saved->{group_name} ) {
        push @log, $file . ": group name different";
    }

    if ( $current->{user_name} ne $saved->{user_name} ) {
        push @log, $file . ": user name different";
    }

    if ( $current->{mtime} != $saved->{mtime} ) {
        push @log, $file . ": mtime different";
    }

    if ( $current->{mode} != $saved->{mode} ) {
        push @log, $file . ": mode different";
    }

}

# confirm
sub confirm {
    my ($message) = @_;
    say $message;
    my $resp = <>;

    if ( $resp =~ /ye?s?/i ) {
        return 1;
    } else {
        return 0;
    }
}

# get checksum, based on selected hash function
sub get_checksum {
    my ($filename) = @_;

    if ( $hash_function eq 'sha1' ) {
        return sha1_checksum($filename);
    } elsif ( $hash_function eq 'md5' ) {
        return md5_checksum($filename);
    } else {
        say "Error: wrong hash function";
        exit;
    }

}

# get sha1 checksum
sub sha1_checksum {
    my ($filename) = @_;
    my $sha = Digest::SHA->new(1);
    $sha->addfile($filename);
    return $sha->hexdigest;
}

# get md5 checksum
sub md5_checksum {
    my ($filename) = @_;
    my $md5 = Digest::MD5->new();
    open FILE, $filename;
    $md5->addfile(*FILE);
    return $md5->hexdigest;
}

# show usage
sub show_usage {

    say <<'END_MESSAGE';
The program must be runnable from the command-line and accept the following command- line arguments:

siv <-i|-v|-h> –D <monitored_directory> -V <verification_file> -R <report_file> -H <hash_function>

The options
-i (indicating initialization mode),
-v (indicating verification mode)
–h (indicating help mode)

are mutually exclusive.

The options -V and -H are mutually exclusive, meaning that you specify the hash function only when you create the verification file (in initialization mode).

In verification mode, the hash function must be recovered from the verification file.
When the help option (-h) is given, the program will print the accepted command-line arguments with a short explanation for each,
and show an example how to run the program in initialization mode and verification mode respectively.

Suppored hashed:

SHA-1 / sha-1 / sha1
MD-5 / md-5 / md5


Example 1: Initialization mode

siv -i -D important_directory -V verificationDB -R my_report.txt -H sha1

Example 2: Verification mode

siv -v -D important_directory -V verificationDB -R my_report2.txt


END_MESSAGE
}

# check if file is in dir
sub is_file_in_dir {
    my ( $file, $dir ) = @_;
    my $file_dir = dirname($file);
    my @file_dirs =
        grep { $_ ne '' } File::Spec->splitdir($file_dir);    # split path to array like some/path => ('some','path')
    my @dir_dirs = grep { $_ ne '' } File::Spec->splitdir($dir);    # and remove empty elements (from start and end)

    # iterare from all parts of directory
    foreach my $dir_part (@dir_dirs) {
        my $file_part = shift @file_dirs;

        unless ($file_part) {    # there is no more parts of file path - we are in different dirs
            return 0;
        }

        if ( $dir_part ne $file_part ) {    # if same part of pile path is not same - we are in different dirs
            return 0;
        }
    }

    return 1;                               # file in dir
}

