### How to compile & load

```sh
$ git clone git://github.com/oleavr/frida-agent-example.git
$ cd frida-agent-example/
$ npm install
$ frida -U -f com.example.android --no-pause -l _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.


mac app:
frida KaiCDemo -l frida-agent-ts/_agent.js

-f TARGET, --file TARGET  spawn FILE
frida -U -l test.js -f net.ioshacker.CrackMe

