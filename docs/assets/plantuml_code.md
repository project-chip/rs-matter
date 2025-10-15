# PlantUML code for generating images

## Pattern B

```plantuml
class "DescHandler" {
  pub new() -> Self
}

interface descriptor::ClusterHandler {
}

DescHandler <|.. descriptor::ClusterHandler
```

## Pattern B1

```plantuml
class "FanModeHandler<H: FanModeHooks>" {
  hooks: H
  pub new(hooks: H) -> Self
}

interface fan_mode::ClusterHandler {
}

interface FanModeHooks {
  const CLUSTER: Cluster<'static>
}

class FanModeDeviceLogic {
}

"FanModeHandler<H: FanModeHooks>" <|.. fan_mode::ClusterHandler
FanModeDeviceLogic <|.. FanModeHooks
"FanModeHandler<H: FanModeHooks>" o-- FanModeDeviceLogic
```

## Pattern C

```plantuml
class "OnOffHandler<'a, H: OnOffHooks, LH: LevelControlHooks>" {
  hooks: H
  level_control_handler: Cell<Option<&'a LevelControlHandler<'a, LH, H>>>
  pub new(hooks: H) -> Self
  pub init(level_control_handler: Option<&'a LevelControlHandler<'a, LH, H>>)
}

interface on_off::ClusterHandler {
}

interface OnOffHooks {
  const CLUSTER: Cluster<'static>
}

class OnOffDeviceLogic {
}

"OnOffHandler<'a, H: OnOffHooks, LH: LevelControlHooks>" <|.. on_off::ClusterHandler
OnOffDeviceLogic <|.. OnOffHooks
"OnOffHandler<'a, H: OnOffHooks, LH: LevelControlHooks>" o-- OnOffDeviceLogic
```
