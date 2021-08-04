# Cobaltstrike4.3_Source

CS的原有特征随着使用者越来越多，被各大厂商设备查杀。从而需要进行二次开发来去除特征。反编译确实是一件比较头疼的事情，看到网上的已经有了反编译出来的4.1的源码。
这里趁空闲之余，反编译了cs4.3。其中大大小小遇到了不少坑点，主要还是反编译代码语法错误导致编译报错的问题。手工修改了大部分反编译导致的语法错误问题。小部分位置代码改动较为复杂，直接进行注释处理，调用原有的jar的类功能进行实现，并不影响功能使用。如需在二开时想改动该位置，可取消注释修改该位置代码进行二开实现。

```
-XX:+AggressiveHeap -XX:+UseParallelGC -javaagent:hook.jar 
```

![image](https://user-images.githubusercontent.com/42479546/128216184-68598146-eedc-47ad-ac23-897bae906296.png)

![AFB~{(86`PQVLCO07QH3B}F](https://user-images.githubusercontent.com/42479546/128214429-74b42ef0-1565-4a24-8818-4f6e7f486700.png)


![image](https://user-images.githubusercontent.com/42479546/128217914-6b240b91-3c7e-4361-8055-bc5a45710ff8.png)


 
