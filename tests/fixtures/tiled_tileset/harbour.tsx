<?xml version="1.0" encoding="UTF-8"?>
<tileset version="1.10" tiledversion="1.11.0" name="harbour" tilewidth="16" tileheight="16" tilecount="64" columns="8">
 <image source="harbour.png" width="128" height="128"/>
 <tile id="0" type="water">
  <properties>
   <property name="swimmable" type="bool" value="true"/>
  </properties>
  <animation>
   <frame tileid="0" duration="200"/>
   <frame tileid="1" duration="200"/>
  </animation>
 </tile>
 <tile id="8" type="planks"/>
 <wangsets>
  <wangset name="Shore" type="corner" tile="-1">
   <wangcolor name="Sand" color="#ffd27f" tile="-1" probability="1"/>
  </wangset>
 </wangsets>
</tileset>
