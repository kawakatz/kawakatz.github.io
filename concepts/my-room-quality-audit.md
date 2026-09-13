# My Room in 3Dとの品質差：配信データ・描画・画面素材の実測監査

調査日：2026-09-09。前の`reference-analysis.md`にある定性的な説明を、今回の計測結果で補う。以下の「現行」は今回の追加修正前のスナップショットを指す。時計・チャット・UV再配置の修正結果は末尾で別に扱う。

## 1. 結論

品質差を「解像度不足」「ポリゴン不足」「高度なレンダラーがない」でまとめる説明は不正確だった。参照の動画は512×256、主な部屋モデルは103,960三角形で、現行デスクの数値より小さい。それでも、完成した映像素材、密に配置されたベイクUV、物ごとの形と陰影が組み合わさって説得力のある画面になっている。

現行には別々の問題がある。

1. **静的モデルのベイクUVが疎い。** 同じ4K画像でも有効な面の割り当てが大きく違う。
2. **画面の原画が簡略化されている。** 参照は完成したサイトと実際の配信画面の動画。こちらはCanvasで作ったUIとゲーム風景で、解像度を増やしても元の情報は増えない。
3. **機器の造形と部品の情報がまだ選択的な近似。** 大まかな寸法を修正したことと、実物らしい各面・文字・接合部を作り切ったことは別である。
4. **参照の見た目は完成済みベイクが中心。** 現行の方が複雑なPBR反射処理をしているが、それだけでは完成絵の質を代替できない。

UV再配置は1に効く。**独立したCanvasTextureであるPC画面・iPad画面・時計には効かない。** 画面素材と時計は別に直す必要がある。「同じ品質になった」と判断できる状態ではない。

## 2. 対象と測定方法

- 参照：[公開リポジトリ](https://github.com/brunosimon/my-room-in-3d/tree/5d00b3f870da81f103e901e0d12e20bbcc816834)。コミット`5d00b3f870da81f103e901e0d12e20bbcc816834`、2021-09-13。
- 主な参照先はユーザーが用意した`my-room-in-3d` のローカルチェックアウト。HEADは上記コミットと一致する。調査開始時にはこのチェックアウトがまだなかったため、計測には先に取得した公開アーカイブ`.scene-build/my-room-audit/my-room-in-3d-main`を使用した。その後、`Baked.js`、`Screen.js`、`roomModel.glb`、`bakedNight.jpg`、`videoStream.mp4`のSHA-256がユーザーのチェックアウトと一致することを確認した。参照の依存関係インストール・開発サーバー・package scriptsは実行していない。参照アセットは製品側へコピーしていない。
- GLBのJSON/accessorを解析して頂点・三角形・属性・素材数を取得。UV座標は既存のBlender/glTFインポーターで復号して集計。画像・動画は`ffprobe`で計測し、動画の5秒時点を抽出して内容を確認した。
- `roomModel.glb`、`bakedNight.jpg`、`videoStream.mp4`は[公開サイト](https://my-room-in-3d.vercel.app/)から配信されるファイルともSHA-256が一致した。少なくともこの3ファイルについて、古いリポジトリだけを見た分析ではない。
- 現行GLBの測定時SHA-256：`240bf3a4fc1a8eafc0b027f8b24781cb1f744e6b02c4a36ab7518427664de3a6`。その後の再ベイクは別の結果になる。

生データ：`.scene-build/my-room-audit/measurements.json`、`uv-measurements.json`、`live-check.json`。再計測用コードは同フォルダの`measure.py`と`mesh_uv.py`。ここでいう三角形数はGLB accessorのindex数÷3で、描画済み画面のピクセル数ではない。

## 3. モデル：参照の方が軽い

| 配信モデル | 頂点数 | 三角形数 | GLBサイズ | メッシュ／primitive | UVセット |
|---|---:|---:|---:|---:|---:|
| roomModel | 69,534 | 103,960 | 276,500 B | 1 / 1 | 3 |
| topChairModel | 8,254 | 14,068 | 32,936 B | 1 / 1 | 1 |
| coffeeSteamModel | 306 | 528 | 1,576 B | 1 / 1 | 1 |
| loupedeckButtonsModel | 56 | 28 | 12,544 B | 14 / 14 | 1 |
| elgatoLightModel | 28 | 26 | 1,424 B | 1 / 1 | 0 |
| googleHomeLedsModel | 16 | 8 | 3,096 B | 4 / 4 | 1 |
| macScreenModel | 4 | 2 | 1,072 B | 1 / 1 | 1 |
| pcScreenModel | 4 | 2 | 1,192 B | 1 / 1 | 1 |
| **参照GLB合計** | **78,202** | **118,622** | **330,340 B** | — | — |
| **現行workstation.glb** | **214,441** | **249,888** | **10,713,028 B** | **9 / 24** | **最大2** |

参照の[アセット一覧](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/assets.js#L7-L28)と[配信GLB](https://github.com/brunosimon/my-room-in-3d/tree/5d00b3f870da81f103e901e0d12e20bbcc816834/static/assets)から計測した。参照では別途コードからロゴ平面も作るので、GLB合計を最終フレーム全体の三角形数とは扱わない。

**確認できた事実：** 参照の全GLBには素材定義・画像・NORMAL属性がない。部屋と椅子は位置とUVを持ち、実行時に同じベイク用ShaderMaterialを割り当てる。主要GLBはDraco圧縮されている。現行はNORMAL、21素材、24 primitiveを持つ非圧縮GLBで、三角形数は参照GLB合計の約2.11倍。ファイルサイズ約32倍の差には圧縮方式と属性数の違いも含まれ、形状密度だけの比較には使えない。[素材割り当て](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Baked.js#L79-L85)、[椅子](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/TopChair.js#L23-L31)、[Dracoローダー](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Utils/Loader.js#L72-L102)。

**現行との具体的な差：** 書き出し前のMacBookは60,600三角形、Mouseは95,796三角形で、キーや丸みを持つ部品の繰り返しに多くを使っている。一方、時計は3パーツ・1,178三角形で、表示面以外の特徴が少ない。この数値はBlenderでの結合・簡略化前なので上のGLB総数とは直接足し合わせない。「全体の分割を増やす」のではなく、見える輪郭・段差・部品・文字に必要な情報を置くべきである。

**未確認：** 公開アーカイブには制作元の`.blend`、ハイポリモデル、ベイク設定がない。どのモデリング手法、サンプル数、ベイク種別を使ったかは配信用GLBだけから断定できない。法線がないことは「平面だけのモデル」という意味でもない。

## 4. ベイク画像とUV：4Kという名前だけでは揃っていない

| 画像 | 寸法 | 配信サイズ | 役割 |
|---|---:|---:|---|
| bakedDay.jpg | 4096×4096 | 1,449,831 B | 昼の完成済み陰影と色 |
| bakedNight.jpg | 4096×4096 | 1,254,801 B | 夜の完成済み陰影と色 |
| bakedNeutral.jpg | 4096×4096 | 1,533,821 B | ニュートラルな色・陰影 |
| lightMap.jpg | 4096×4096 | 866,346 B | RGBに別々の照明マスク |
| 現行desk-daylight.jpg | 4096×4096 | 1,543,578 B | 拡散光・色、0〜4を縮小符号化 |
| 現行desk-occlusion.jpg | 2048×2048 | 1,168,202 B | 反射用の接触遮蔽 |
| 現行desk-contact.png | 1024×1024 | 61,247 B | 床への接触影と透過 |

JPEGはいずれも8bit YUV 4:2:0。参照の昼・夜・ニュートラルは同じUVに重ねる別状態であり、4枚あるから空間解像度が16Kになるわけではない。[画像の読み込みと割り当て](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Baked.js#L35-L48)。

### UVの面積を測ると大きな差がある

各三角形をUV上へ投影し、面積の絶対値を合計した。

| ベイク対象 | UV三角形の面積合計／単位正方形 |
|---|---:|
| 参照roomModel、UV0 | 0.796873（79.69%） |
| 参照topChairModel、UV0 | 0.026052（2.61%） |
| 参照の両モデル合計 | 0.822926（82.29%） |
| 現行の静的workstation-baked、UV0 | 0.203922（20.39%） |

これは**面積合計であり、重なりを除いたピクセル被覆率ではない**。UVが重なっていない場合に、利用面積の目安になる。参照では部屋と椅子が同じベイク画像を使う。画像を直接見ると参照は大小の面が密に詰まっており、現行には多数の微小な島と広い余白がある。

面積比は約4.04だが、「全ての物が2倍鮮明になる」とは言えない。物ごとの割り当て、カメラ投影、ミップマップ、画面上の大きさが違う。とはいえ、現行はデスクだけに4Kを使いながら、参照の部屋全体の4Kより面積を有効に使えていない。8K化を先に行う前に直せる実装上の損失である。

修正前は全静的パーツを結合し、`smart_project(angle_limit=66°, island_margin=.004, area_weight=.3)`で一括展開していた。大量の小さな部品・面に一定の島間余白が付き、パッキング効率が落ちる構造になっていた。余白値だけが原因だとは断定せず、再配置前後の面積・島の接触・ベイク漏れを比較する必要がある。[現在のUV処理（再配置を含む）](../tools/bake-scene.py#L173)

参照GLBにあるUV1・UV2は範囲外座標や重なりを持つが、配信中のベイクシェーダーが使うのはUV0だけである。3セット分の解像度を足して評価してはいけない。[vertex shader](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/shaders/baked/vertex.glsl#L1-L11)。

## 5. 素材と照明：参照はPBRの高度さで勝っているのではない

参照の既定値は`uNightMix=1`、`uNeutralMix=0`。まず昼・夜・ニュートラルの画像を補間し、lightMapのRからTV、BからPC、Gからデスクの照明マスクを取り出す。それぞれピンク`#ff115e`、青`#0082ff`、オレンジ`#ff6700`をlightenブレンドで重ねる。既定の強度は1.47、1.4、1.9。[既定値](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Baked.js#L50-L73)、[合成順序](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/shaders/baked/fragment.glsl#L25-L42)。

lightenは、色成分ごとの最大値と元の色を指定強度で混ぜる処理で、実行時の物理的な光輸送計算ではない。[ブレンド実装](https://github.com/jamieowen/glsl-blend/blob/master/lighten.glsl)。参照の夜景では物の面を分ける暖色・寒色、暗い部分、縁の明るさがベイク画像自体に既に含まれている。昼の画像にも木の方向、キー、接合部、接触部分の陰影が入っている。

現行はCyclesのDIFFUSEベイクを浮動小数点で作り、−2 EVのsRGB JPEGと実行時4倍復元で明るい部分を保持する。その上にRoomEnvironment由来の反射と物理素材のspecularを加え、AgXを適用する。これは前の白飛びを直す正しい改善だが、参照と同じ描画方式ではない。現行の方が実行時の材質処理は複雑でも、ベイク前の造形・色・反射の配置が未完成なら質感は揃わない。[現行のベイク](../tools/bake-scene.py#L194)、[現行の素材処理](../assets/js/desk.js#L65)

参照のカスタムシェーダーは最後に色を直接出力し、標準のtone-mapping/encodingチャンクを明示的に挿入していない。`outputEncoding=sRGBEncoding`というRenderer設定だけを見て、現行の線形計算＋AgXと同じ色処理だと判断してはいけない。旧Three.jsの色管理を現代の推奨実装としてそのまま移植する意図もない。

## 6. 画面：低解像度でも「中身」が完成している

| 動画 | 表示先 | 寸法 | 更新 | 長さ | 映像ビットレート | サイズ |
|---|---|---:|---:|---:|---:|---:|
| videoPortfolio.mp4 | PCモニター | 512×256 | 30 fps | 14.533秒、436フレーム | 1.020 Mbps | 1,858,149 B |
| videoStream.mp4 | Mac側画面 | 512×256 | 30 fps | 29.033秒、871フレーム | 1.032 Mbps | 3,755,014 B |

両方ともH.264、YUV420p、音声ストリームなし。`muted/loop/playsInline/autoplay`のvideo要素をVideoTextureにして、独立した2三角形の画面メッシュへ貼る。uv範囲は0〜1で、ソース側にクロップや繰り返し指定はない。動画の2:1と実際の画面形状の比率は完全には一致していないので、参照も全ての細部を寸法通りに再現しているわけではない。[動画の割り当て](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/World.js#L72-L81)、[video/texture/material](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Screen.js#L25-L47)。

**抽出フレームで確認した内容：** Portfolioは作者の完成した3Dポートフォリオを映した動画。Streamは実際のコードエディター、部屋の制作画面、人物のカメラ映像を含む配信画面である。文字が全て判読できる解像度ではなくても、ウィンドウ、文字密度、操作、人物の動きの関係が自然に揃っている。

**現行との違い：** Windowsは1536×864、Macは1536×998、iPadは1536×1152のCanvas。画面のピクセル数は参照より多いが、更新はWindows 4 fps、Mac 6 fps、iPad 12 fps、大画面4 fps。参考作品の30 fps動画と比べ、動きの連続性にも差がある。[現行の画面生成](../assets/js/screens.js#L44)、[更新周期](../assets/js/screens.js#L331)

UIを細かく描き直した後も、ゲームの地形、手、HUD、配信者の顔、チャットなどは自作の簡略表現である。画面を「Windows」「Codex」「YouTube」と読めるようにしたことと、本物のデスクトップ映像の情報を持たせたことを区別する必要がある。画面素材の改善では、実際にそのアプリを使うとどういうウィンドウ配置・文字・余白・スクロール・カーソル変化になるかを詰める。動画を採用する場合は自作・使用可能な素材を作る工程が必要で、参照動画を流用する話ではない。

## 7. 時計と機器の細部

参照リポジトリに、ユーザーのSeiko BC402Kを再現した時計アセットや専用コードは確認できない。したがって「参照の時計の方式」を発見したとは扱わない。ここはユーザーの実写真・機器仕様と、現行の作り込みの不足を照合する。

修正前の時計は灰緑色の単色面に100pxのmonospace時刻、29pxの英語日付を描いた512×256の画像。時計の筐体も3パーツである。BC402KらしいLCDの区画、数字のセグメント、曜日・温湿度・快適度の表示、枠の段差などを省いており、テクスチャのピクセル数を上げてもこれらの情報は現れない。

PC・iPadは公称寸法や画面比率を直し、機種別の蓋・ベゼル・キーボード・ホームボタンを持つようになった。しかし、キーは共有レイアウト由来の自作形状で、Mac80キー、Mouse105キーのJIS風近似。メーカーCADや全ての刻印・ポート・筐体断面の完全再現ではない。小さな輪郭の段差、表面の仕上げ、実際の文字の大きさは別の観察項目である。[キー配置と文字](../assets/js/keyboard.js#L3)

接近表示では刻印の弱さも確認した。最終GLBの刻印面はキー上面から0.120mm上にあり、サンプルしたキーのUVはCanvas上の描画位置と0.07px以内で一致した。ブラウザーでも刻印画像と面そのものの表示を確認でき、座標・素材割り当て・面の欠落を示す結果はなかった。一方、本体幅280pxのMacBookをNotes接近時の角度で見ると、3mmの文字の大文字部分は約1pxまで縮む。刻印面が存在することだけでは、最終画面で機器らしい情報が見えることを保証しない。これは画面内UIの原画品質とは別の、投影サイズと細部の見せ方の課題である。

## 8. 描画設定・フィルター・動き

| 項目 | 参照 | 現行／含意 |
|---|---|---|
| Three.js | 0.130.1 | 0.186.0。新しいだけでは視覚品質は決まらない |
| DPR上限 | 2、下限1 | 現行も上限2 |
| アンチエイリアス | WebGLRendererの`antialias:true` | 現行も有効 |
| ポスト処理 | Composerは作るが`usePostprocess=false` | 特殊なブルーム・SSAOが品質の必須条件ではない |
| リアルタイム影 | shadowMap有効化なし | 主要な影はベイク側で完成している |
| 背景 | `#010101`、不透明 | 現行は透明キャンバスと明るいページ背景 |
| カメラ | 透視投影、FOV20° | 現行24°。画角を揃えるだけで素材は増えない |
| ベイク画像フィルター | Linear拡大、LinearMipmapLinear縮小、anisotropy既定1 | 現行のベイク画像は最大anisotropy。参照だけが高品質フィルターを持つわけではない |
| 動画フィルター | Linear、ミップなし | 低解像度の完成映像を継続更新 |
| シーン更新 | 継続requestAnimationFrame | 現行は静止・非表示で停止し、画面更新に上限がある |

[Renderer](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Renderer.js#L19-L51)、[通常の直接描画](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Renderer.js#L112-L119)、[DPR](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Experience.js#L71-L83)、[カメラ](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/Camera.js#L25-L29)、[旧Texture既定値](https://github.com/mrdoob/three.js/blob/r130/src/textures/Texture.js#L20-L61)、[旧VideoTexture](https://github.com/mrdoob/three.js/blob/r130/src/textures/VideoTexture.js#L5-L26)。

今回のブラウザー比較は両方native DPR1。参照は1280×720、現行は1253×1173のページ内に1253×1003のキャンバスを持ち、CSSの表示寸法とキャンバス解像度は一致していた。**低解像度のキャンバスをCSSで拡大していた証拠はない。** ただし比較領域の縦横比と物の投影サイズが異なるため、見た目を比べる際は対象機器の表示幅も揃える必要がある。

参照の動きは画面動画だけではない。椅子の上部は正弦波で左右に回転、Google HomeのLEDは位相をずらして点滅、ロゴは画面内を移動し、コーヒーの湯気は専用シェーダーで動く。これらは静的な完成絵を局所的に動かす設計で、全オブジェクトを毎フレーム物理計算しているのではない。[椅子](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/TopChair.js#L35-L37)、[LED](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/GoogleLeds.js#L91-L95)、[更新対象](https://github.com/brunosimon/my-room-in-3d/blob/5d00b3f870da81f103e901e0d12e20bbcc816834/src/Experience/World.js#L88-L103)。

## 9. 今回の修正と残る確認

この監査の数値はUV再配置前、時計・iPadチャットの追加修正前の基準値である。修正後の値をそのまま上書きせず、前後を比較できるようにする。

今回の修正として、UVを`pack_islands`のCARDINAL回転・CONVEX形状・FRACTION余白8/4096で再配置した。最終モデルのUV三角形面積合計は**20.39%から54.27%**へ増えた。昼のベイク余白は8px、AOは4px。再ベイクの最大拡散輝度は**3.683**で、符号化範囲0〜4に収まった。面積合計の改善は約2.66倍だが、画質や全機器の解像度が一律2.66倍になったことは意味しない。島間隔の確認は試験モデルのサンプルに限り、全島の非重複を網羅的に検証した結果ではない。

時計の形状・[新しいLCD描画](../assets/js/clock.js#L7)と、iPadの右側チャット表示も別に変更した。UV修正で自動的に改善したものではない。最終GLBは266,783三角形、10,863,500 B、SHA-256は`d53d1671a778e0b1f885718894f343c337020788f62b46d7f364526e0cd16cfc`。上の比較表は修正前の測定値を保持する。

| 対象 | 確認項目 | 改善しても残る範囲 |
|---|---|---|
| 静的UV再配置 | 面積、島の重なり、境界の色漏れ、同じ表示サイズでの天板・筐体の見え方 | 独立した画面・時計の原画は変わらない |
| 時計 | 実機らしいLCD区画・セグメント・文字比率、遠景での見え方 | 単に時間が更新されることは造形の忠実さを証明しない |
| iPadチャット | 配信画面としての構成・文字密度・動画領域との比率 | ゲーム・人物などプログラムで描いた原画の簡略さは残る |
| 全体 | デスク全景と機器接近、同じ投影サイズで参照と比較 | ビルド・リンク・操作テストの成功は視覚品質の合格を意味しない |

今回の調査で、まず直すべき損失と、描画設定では補えない制作上の不足を分離できた。今後の品質判断は個々の機器・画面の比較で行い、4K、ポリゴン数、PBRという名称を達成基準にしない。
