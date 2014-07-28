#!/usr/bin/perl
#このスクリプトは ISG1000 用です
#またコンフィグは fw.config で同じディレクトリに保存している必要があります。


use strict;
use warnings;

sub file_open{
  my $handle = undef;
  open($handle, '<', 'fw.config') or die "$!";

  return $handle;
}

sub file_close{
  my $handle = shift;

  if (defined $handle){
    close $handle;
    $handle = undef;
  }
}


#この関数を呼び出すとすべての処理を行う
sub extraction{
  my $handle = shift;
  my $addr = shift;

  my ($private_addr, $policy) = &file_extraction($handle, $addr);

  if (!defined($private_addr)){
    print "address not found\n";
    exit;
  }

  &print_mip($addr,$private_addr);

  if (!defined($policy)){
    print "policy not found\n";
    exit;
  }

  my @list = &separate($policy);
  my $retrun_line;
  foreach my $line (@list){
    my ($id, $disable, $src, $service) = &element_extraction($line);
    &print_id($id, $disable);

    my ($src_int, $src_char) = &int_char_separate(@$src);
    my @src_int = &addr_sort(@$src_int);
    &print_policy(\@src_int, \@$src_char, \@$service);
    }
}

#コンフィグファイルから
#プライベートアドレスとポリシーの抽出を行う関数を呼び出し
#結果をまとめて戻り値として返す
sub file_extraction{
  my $handle = shift;
  my $addr = shift;
  my $private_addr;
  my $policy;
  while(<$handle>){
    my $private_addr_tmp = &file_mip_extraction($_, $addr);
    if ($private_addr_tmp){
      $private_addr = $private_addr.$private_addr_tmp;
    }

    my $policy_tmp = &file_policy_extraction($_, $addr);
    if ($policy_tmp){
      $policy = $policy.$policy_tmp;
    }
  }
  return ($private_addr, $policy);
}

#コンフィグファイルからプライベートアドレスを抽出する
#set interface \"ethernet1\/1\" mip $addr host (.+) netmask
#を抽出する
sub file_mip_extraction{
  my $private_addr;
  my ($file_line, $addr) = @_;
  if ($file_line =~ /set interface \"ethernet1\/1\" mip $addr host (.+) netmask/){
    $private_addr = $1;
  }
  if ($private_addr){
    return $private_addr;
  }
  return ;
}

#コンフィグファイルからポリシーの抽出を行う
#該当するポリシーが複数ある場合もひとつの変数として戻り値を返す
#set policy id ...... exit までを抽出する
sub file_policy_extraction{
  my $policy;
  my ($file_line, $addr) = @_;
  if ($file_line =~ /\"MIP\($addr\)"/ .. /^exit/) {
    $policy = $_;
  }
  if ($policy){
    return $policy;
  }
  return;
}

#exit 区切りでポリシーを分割し、配列を戻り値として返す
sub separate{
  my $data = shift;
  my @list = split(/exit/,$data);
  pop(@list);
  return @list;
}

#抽出されたポリシーのコンフィグの中から
#id, src-addr, service を抽出する
sub element_extraction{
  my $line = shift;
  my ($id, @src, @service);
  my $disable = "";
  while ($line =~ /set policy id (.+) from \"Untrust\" to \"Global\"  \"(.+)\" \"(.+)\" \"(.+)\" permit/g){
    $id = $1;
    @src = ($2);
    @service = ($4);
  }
  while ($line =~ /set policy id \d+ disable/g){
    $disable = "disable";
  }
  while ($line =~ /set src-address \"(.+)\"/g){
    push(@src, $1);
  }
  while ($line =~ /set service \"(.+)\"/g){
    push(@service, $1);
  }

  return ($id, $disable, \@src, \@service);

}

#IPアドレスのソートを行うため、抽出された src_addr を
#数字と文字列に分割する
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

#IPアドレスをソートする
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

#mip についての表示
sub print_mip{
  my $addr = shift;
  my $private_addr = shift;
  print "\n------------------\n";
  print "MIP:$addr\nPrivate:$private_addr\n\n";
}

#id についての表示
sub print_id{
  my $id = shift;
  my $disable = shift;
  print "------------------\n";
  print "ID:$id\t$disable\n\n";
}

#ポリシーを表示をコントロールする関数
sub print_policy{
  my ($src_int, $src_char, $service) = @_;
  my @src = (@$src_int, @$src_char);
  my $src_addr_results = &data_forming(@src);

  &print_src_addr($src_addr_results);
  &print_service(@$service);
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

#src-addr の表示
sub print_src_addr{
  my $src_addr_results = shift;
  print "src-address:\n$src_addr_results\n\n";
}

#サービスの表示
sub print_service{
  my @service = @_;
  my $service_results = join(", ", @service);

  print "service:\n$service_results\n\n";
}

sub argv_check {
  if (!$ARGV[0]){
    print "Usage : ./fw.pl <address>\n";
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

#コンフィグファイルから global アドレスを抽出
sub file_private_extraction{
  my $handle = shift;
  my $addr = shift;

  my $global = "";

  while(<$handle>){
    if (/set interface \"ethernet1\/1\" mip (.*) host $addr netmask/){
      $global = $1;
    }
  }

  return ($global);
}

#####################################
#以下実行時の処理

#引数の有無のチェック
&argv_check();

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

#ハンドラは中身を取り出すと消えてしまうので開き直す
$handle = &file_open();

#処理を行う関すの呼び出し
&extraction($handle, $addr);

&file_close($handle);

