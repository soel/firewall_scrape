#!/usr/bin/perl
#このスクリプトは FG300C 用です。
#またコンフィグは fw.conf で同じディレクトリに保存している必要があります。
#

use strict;
use warnings;

########################################
#以下関数

sub file_open{
  my $handle = undef;
  open($handle, '<', 'fw.conf') or die "$!";

  return $handle;

}

sub file_close{
  my $handle = shift;

  if (defined $handle){
    close $handle;
    $handle = undef;
  }
}

#コンフィグ内から該当部分について抜き出す
sub file_extraction{
  my $handle = shift;
  my $addr = shift;

  my $prev;
  my $fw_pol = "";
  my $fw_mip = "";
  my $id;

  while(<$handle>){
    if (/set dstaddr \"$addr\"/ .. /next/){
      if ($prev =~ /set srcadd/){
        $fw_pol = $fw_pol.$id.$prev.$_;
      }
      $fw_pol = $fw_pol.$_;
    }
    if (/edit \"$addr\"/ .. /next/){
      $fw_mip = $fw_mip.$_;
    }
    if (/edit \d+/){
      $id = $_;
    }
    $prev = $_;
  }

  return ($fw_mip, $fw_pol);
}

#id ごとに分けて配列に格納する
sub policy_split{
  my $fw_pol = shift;

  my @list = split(/next/,$fw_pol);
  pop(@list);

  return @list;
}

#mip アドレスを抽出し、表示する関数を呼び出す
sub mip_extraction_print{
  my $fw_mip = shift;
  my $addr = shift;
  my $local_addr;

  if ($fw_mip =~ /set mappedip (.+)/){
    $local_addr = $1;
  }

  if (!defined($local_addr)){
    print "address not found\n";
    exit;
  }

  &print_mip($addr, $local_addr);

}

#id ごとにまとめられた配列から各要素を抽出する関数をよびだし、
#抽出したあと表示する関数を呼び出す
sub policy_extraction_print{
  my @fw_pol_list = @_;

  #抽出した文字列を配列ごとに処理
  foreach my $line (@fw_pol_list){
    #id を抽出
    my $id = &id_extraction($line);

    #src アドレスの抽出
    my @src = &src_extraction($line);

    #src アドレス内の文字列部と数字部(ip address)の分離
    my ($src_int, $src_char) = &int_char_separate(@src);

    #ip address のソート
    my @src_int_sort = &addr_sort(@$src_int);

    #ip address の整形
    my $src_int_result = &data_forming(@src_int_sort);

    #文字列部の整形
    my $src_char_result = &data_forming(@$src_char);

    #サービスの整形
    my $service = &service_extraction($line);

    #整形した各データを表示
    &print_policy($id, $src_int_result, $src_char_result, $service);

  }
}

#id の抽出
sub id_extraction{
  my $line = shift;
  my $id;

  if ($line =~ /edit (\d+)/){
    $id = $1;
  }

  if (!defined($id)){
    print "policy not found\n";
    exit;
  }

  return $id;
}

#srcaddr を抽出
sub src_extraction{
  my $line = shift;
  my @src;

  if ($line =~ /set srcaddr (.+)/){
    my @tmp = split(/ /,$1);
    foreach my $item (@tmp){
      if ($item =~ /\"(.+)\"/){
        push(@src,$1);
      }
    }
  }
  return @src;
}

#service を抽出
sub service_extraction{
  my $line = shift;
  my $service ="";
  my @services;

  if ($line =~ /set service (.+)/){
    my @tmp = split(/ /,$1);
    foreach my $item (@tmp){
      if ($item =~ /\"(.+)\"/){
        push(@services,$1);
      }
    }
  }
  $service = join(", ", @services);

  return $service;
}

#IPアドレスのソートを行うため、抽出された src_addr を
#数字と文字列に分割
sub int_char_separate{
  my @src = @_;
  my @src_int;
  my @src_char;
  foreach my $src_addr (@src){
    if ($src_addr =~ /^\d+/){
      push(@src_int, $src_addr);
    }else{
      push(@src_char, $src_addr);
    }
  }
  return (\@src_int, \@src_char);
}

#IPアドレスをソート
sub addr_sort{
  my @src_int = @_;
  @src_int = sort {
    my @a = $a =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
    my @b = $b =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/;
    $a[0] <=> $b[0] ||
    $a[1] <=> $b[1] ||
    $a[2] <=> $b[2] ||
    $a[3] <=> $b[3]
  } @src_int;

  return @src_int;
}

#データの整形 要素 2つにつき 1つ \n を入れる
sub data_forming{
  my @data = @_;
  my $i = 0;
  my $data_results;
  foreach my $data_item (@data){
    if ($i == 0){
      $data_results = $data_item;
    }elsif ($i % 2 == 1){
      $data_results = $data_results.", ".$data_item;
    }else{
      $data_results = $data_results.",\n".$data_item;
    }
    $i += 1;
  }
  return $data_results;
}

#mip についての表示
sub print_mip{
  my $addr = shift;
  my $private_addr = shift;
  print "\n------------------\n";
  print "MIP:$addr\nPrivate:$private_addr\n\n";
}

#ID, src-address, service について表示
sub print_policy{
  my $id = shift;
  my $src_int_result = shift;
  my $src_char_result = shift;
  my $service = shift;

  print "------------------\n";
  print "ID:$id\n\n";

  if ($src_char_result){
    if ($src_int_result){
      print "src-address:\n$src_int_result,\n$src_char_result\n\n";
    }else{
      print "src-address:\n$src_char_result\n\n";
    }
  }else{
    print "src-address:\n$src_int_result\n\n";
  }

  print "service:\n$service\n\n";
}

#引数がなければ使い方を表示
sub argv_existence_check {
  if (!$ARGV[0]){
    print "Usage : ./new_fw.pl <address>\n";
    exit;
  }
}

#引数が private アドレスかを正規表現でチェック
sub argv_address_check {
  my $addr = shift;

  #クラスA
  if ($addr =~ /^10\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/){
    return "private";
  }

  #クラスB
  if ($addr =~ /^172\.(1[6-9]|2\d|3[0-1])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/){
    return "private";
  }

  #クラスC
  if ($addr =~ /^192\.168\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/){
    return "private";
  }

  #上記以外 = global
  return "global";
}

#private アドレスから global アドレスを抽出する関数
sub file_private_extraction{
  my $handle = shift;
  my $addr = shift;

  my $prev = "";
  my $prev2 = "";
  my $global = "";

  while(<$handle>){
    if (/set mappedip $addr$/){
      if ($prev2 =~ /set extip (.*)/){
        $global = $1;
      }
    }
    $prev2 = $prev;
    $prev = $_;
  }

  return ($global);
}

#####################################################
#以下実行した時の処理

#引数の有無のチェック
&argv_existence_check();

my $addr = $ARGV[0];

#private global のアドレス判定
my $address_check = &argv_address_check($addr);


my $handle;

#private アドレスが引数だった場合の処理
if ($address_check eq "private"){
  $handle = &file_open();

  #$addr を global アドレスに上書
  $addr = &file_private_extraction($handle, $addr);

  &file_close($handle);
}


$handle = &file_open();

#アドレスを元に mip 情報, ポリシー情報をコンフィグファイルから抽出
my ($fw_mip, $fw_pol) = &file_extraction($handle, $addr);

&file_close($handle);

#mip 情報の整形と表示
&mip_extraction_print($fw_mip, $addr);

#ポリシー情報を ID ごとにまとめて配列にする
my @fw_pol_list = &policy_split($fw_pol);

#IDごとにまとめられた配列の情報を整形して表示
&policy_extraction_print(@fw_pol_list);

