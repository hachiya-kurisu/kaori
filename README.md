# kaori

a neon-drenched gemini server

stumbling through the alleys
are you moving away from something or towards something?
away from someone? towards someone?
the streetlight above you flickers for a moment
everything goes dark

named after makimura kaori (槇村香) from city hunter

made for openbsd, might work elsewhere

## a low simmer of desire hums in the air

first, hit play on GET WILD by TM NETWORK.
feel the city's pulse kicking in, then... let's get moving.
you've got until the song finishes, so no distractions, ok?

```
$ make config.h
$ vim config.h # tweak to your pleasure
$ make && make install
$ rcctl enable kaori
$ rcctl start kaori
```

## echo through the city's pulse

* kaori listens on ::1
* combine with relayd to share with the world

## geminispace

[project gemini](gemini://geminiprotocol.net/)

[my capsule](gemini://higeki.jp/)
[manatsu](gemini://manatsu.town/)

## author

[蜂谷栗栖](https://blekksprut.net/)
