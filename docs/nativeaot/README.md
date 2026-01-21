# NativeAOT

Hytale is a game written in C#, and compiled to a native binary using NativeAOT.

NativeAOT gets rid of the Just-in-time compiler used by the .NET runtime, and potentially performs additional optimizations to increase the performance of the target application. This is great for games, but bad for modders, as a .NET binary (CIL) is much, *much* easier to reverse engineer than a native binary.

Luckily, NativeAOT is not the same as rewriting the program to C++ and compiling it, and actually stores a bunch of metadata in the final binary we can use to our advantage. There are quite a few articles about reverse engineering NativeAOT binaries, but the one that started this all is [Recovering Metadata from .NET Native AOT Binaries](https://blog.washi.dev/posts/recovering-nativeaot-metadata/) by [Washi](https://github.com/Washi1337).

The article takes a deep dive into the inner working of NativeAOT, and the fact it includes metadata that we can use to our advantage to make reverse engineering easier. The following segments assume you have read and at least partially understand what the article talks about.

## Nothing to hydrate

Unfortunately, starting from .NET 10 and up, Windows NativeAOT binaries [no longer contain dehydrated data by default](https://github.com/dotnet/runtime/commit/af5972ec48da98571e5a72d4cb2ce4b94368836f). An alternative way to finding MethodTables is by just scanning the data sections of the image, locating the System.Object MethodTable (which follows a pretty specific pattern, making it easily discernible), and then re-scanning the data section over and over again, slowly creating a graph of MethodTables that have System.Object and each other as their base type. This has since been implemented in the [ghidra-nativeaot](https://github.com/Washi1337/ghidra-nativeaot/pull/17) plugin, and the same technique is also used by the [aot-experiments](../../aot-experiments/) tool to find all MethodTables.

## Frozen Objects

I have not yet taken a dive into frozen objects, so not much to say about that for now.

## So now what?

We now have a list of MethodTables, but their names aren't really all that useful, and dealing with a bunch of Class_&lt;address&gt; would be kind of a hassle.
Wouldn't it be great if we can find out the name of each of these MethodTables? But that sounds a little too good to be true... or does it?

## Runtime Reflection

A notable feature in C# (and .NET in general) is [Reflection](https://learn.microsoft.com/en-us/dotnet/fundamentals/reflection/overview). Reflection allows you to dynamically do a lot of things within the .NET ecosystem, for example, calling a function by it's name dynamically (without knowing the name beforehand).

```cs
typeof(Program).GetMethod("MyFunction").Invoke(null, null);

private static void MyFunction() {
    Console.WriteLine("Hello World");
}
```

Or serialization, for example using Newtonsoft.Json.

As this is normally not possible in native binaries (or at least, not dynamically without codegen), NativeAOT embeds Reflection Metadata inside the binary, which can be used during runtime to resolve types, methods, fields, properties, events, etc. We can use this to our advantage to enrich a decompiled version of the binary with structures and fully qualified method names.

Unfortunately (and here comes the too good to be true bit), this metadata is not complete. If the compiler determines that methods cannot be invoked via reflection, or a struct does not need dynamic field access, its metadata is not included in the output image, meaning we lose information. At the time of writing, around 20k methods out of the 65k methods in the image have known metadata. Most of these methods seem to be delegates or enumerator generated methods (although for some reason the Main entrypoint is embedded in the metadata).

## TODO

Maybe add a section about: finding the RTR header, RTR sections, reflection blobs, fixup tables, native hashtables, metadata reading