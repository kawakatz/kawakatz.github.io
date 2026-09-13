import { CanvasTexture, SRGBColorSpace } from 'three';

// English Ultra Fantasy Ruby Red: genuine silver claw, pink characters and cyan robots.
export function createCanTexture() {
  const canvas = document.createElement('canvas');
  canvas.width = 2048; canvas.height = 1536;
  const ctx = canvas.getContext('2d');
  const ink = '#111216', pink = '#e83d98', pale = '#ed83b8', blue = '#51aacc';
  // Contours from the official flat Ruby Red mark, preserving its 84:122 silver silhouette.
  const claw = new Path2D(
    'M64,71 L65,63 L63,62 L63,45 L61,44 L61,38 L62,38 L61,34 L60,34 L58,31 L53,31 L53,30 L51,30 L51,31 L49,31 L49,35 L48,35 L49,38 L45,40 L45,49 L46,49 L46,52 L44,53 L44,59 L45,59 L44,64 L46,65 L46,69 L47,69 L47,71 L48,71 L49,74 L48,74 L48,76 L47,76 L47,78 L46,78 L46,82 L47,82 L46,88 L48,88 L48,91 L47,91 L46,98 L45,98 L45,102 L44,102 L45,109 L46,109 L46,111 L45,111 L45,117 L44,117 L44,118 L45,118 L45,124 L44,124 L45,132 L44,132 L44,131 L43,131 L43,125 L42,125 L41,115 L40,115 L40,113 L39,113 L39,112 L40,112 L39,103 L37,102 L37,99 L38,99 L38,97 L39,97 L39,95 L40,95 L40,86 L39,86 L39,84 L38,84 L38,82 L39,82 L38,77 L39,77 L39,76 L38,76 L38,72 L37,72 L36,66 L35,66 L35,64 L34,64 L34,62 L33,62 L33,61 L34,61 L34,56 L35,56 L35,53 L36,53 L36,44 L35,44 L35,42 L33,41 L33,36 L32,36 L31,34 L26,34 L26,33 L21,32 L21,31 L24,31 L24,30 L26,30 L26,29 L33,29 L33,28 L35,28 L35,27 L37,27 L37,26 L40,26 L41,28 L50,29 L50,28 L53,28 L54,26 L59,26 L59,25 L61,25 L61,24 L65,24 L65,23 L68,23 L68,22 L70,22 L70,23 L76,25 L76,26 L77,26 L77,29 L80,30 L80,31 L78,31 L78,32 L76,33 L76,36 L75,36 L74,39 L73,39 L73,42 L74,42 L73,46 L74,46 L74,48 L75,48 L74,54 L75,54 L75,57 L76,57 L76,60 L74,61 L73,72 L74,72 L74,75 L75,75 L75,78 L76,78 L76,79 L75,79 L75,82 L72,84 L72,88 L71,88 L71,90 L70,90 L70,92 L69,92 L69,110 L68,110 L68,111 L69,111 L69,116 L68,116 L68,121 L69,121 L69,123 L71,124 L71,126 L70,126 L70,131 L69,131 L69,136 L68,136 L68,142 L67,142 L67,144 L66,144 L66,134 L65,134 L65,131 L63,130 L63,128 L64,128 L65,125 L64,125 L64,120 L63,120 L63,119 L64,119 L63,102 L62,102 L62,100 L61,100 L62,94 L63,94 L63,92 L64,92 L65,84 L66,84 L66,79 L65,79 L64,71Z ' +
    'M95,96 L96,96 L96,95 L95,95 L96,86 L95,86 L95,81 L94,81 L94,74 L95,74 L95,72 L94,72 L94,70 L93,70 L93,68 L92,68 L92,65 L91,65 L91,64 L92,64 L91,55 L93,54 L93,41 L94,41 L94,40 L92,39 L92,37 L89,37 L89,36 L84,37 L84,36 L80,35 L80,33 L82,33 L82,32 L89,31 L90,28 L93,27 L94,25 L95,25 L95,26 L99,26 L101,29 L103,29 L102,32 L105,34 L105,36 L104,36 L105,40 L104,40 L104,42 L103,42 L103,45 L101,46 L100,53 L98,54 L98,59 L99,59 L98,63 L100,64 L98,73 L99,73 L99,75 L100,75 L101,78 L102,78 L102,81 L101,81 L102,84 L101,84 L101,86 L100,86 L100,88 L99,88 L100,99 L98,100 L98,104 L99,104 L99,109 L98,109 L99,118 L97,119 L97,122 L96,122 L95,126 L93,126 L94,118 L93,118 L92,113 L94,112 L95,96Z '
  );
  const stock = ctx.createLinearGradient(0, 0, 0, 1536);
  stock.addColorStop(0, '#eb52a3'); stock.addColorStop(.5, pink); stock.addColorStop(1, '#df328d');
  ctx.fillStyle = stock; ctx.fillRect(0, 0, 2048, 1536);
  ctx.lineCap = 'round'; ctx.lineJoin = 'round';
  function path(d, fill = null, width = 3, stroke = ink) {
    const shape = new Path2D(d);
    if (fill) { ctx.fillStyle = fill; ctx.fill(shape); }
    ctx.strokeStyle = stroke; ctx.lineWidth = width; ctx.stroke(shape);
  }
  function oval(x, y, rx, ry, fill, width = 3) {
    ctx.beginPath(); ctx.ellipse(x, y, rx, ry, 0, 0, Math.PI * 2);
    ctx.fillStyle = fill; ctx.fill(); ctx.strokeStyle = ink; ctx.lineWidth = width; ctx.stroke();
  }
  function dot(x, y, r = 4, color = ink) {
    ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
  }
  function heart(x, y, size = 1) {
    ctx.save(); ctx.translate(x, y); ctx.scale(size, size);
    path('M0 18 C-31 0-29-22-12-19 Q-3-18 0-9 Q10-25 23-15 C39 1 13 16 0 18Z', blue, 2.5); ctx.restore();
  }
  function flower(x, y, r, petals = 6) {
    ctx.save(); ctx.translate(x,y);
    for (let i = 0; i < petals; i++) {
      ctx.save(); ctx.rotate(i*Math.PI*2/petals); oval(0,-r*.63,r*.35,r*.49,pink,2.5); ctx.restore();
    }
    oval(0,0,r*.35,r*.35,pink,2.5); dot(-r*.10,-r*.06,1.7); dot(r*.10,-r*.06,1.7);
    path(`M${-r*.13} ${r*.10} Q0 ${r*.27} ${r*.13} ${r*.10}`,null,1.5); ctx.restore();
  }
  // The left strip has the recognizable rounded bear and bunny-burger figures.
  function bear(x,y,scale=1) {
    ctx.save();ctx.translate(x,y);ctx.scale(scale,scale);
    path('M-60-75 C-101-128-64-157-34-120 Q2-139 36-119 C69-159 106-116 67-76 C88-47 86-10 79 23 L75 125 Q60 151 37 128 L32 83 Q0 66-32 83 L-37 129 Q-61 151-79 123 L-84 27 Q-88-36-60-75Z',pink,4);
    path('M-57-92 Q-73-125-54-129 M55-92 Q72-124 56-131 M-76 18 Q-52-4-35 21 L-34 82 M76 18 Q53-4 35 21 L34 82',null,2.5);
    oval(-29,-54,5,8,ink,1);oval(30,-54,5,8,ink,1);
    path('M-9-35 Q0-44 9-35 Q9-25 0-24 Q-9-25-9-35Z',ink,1.5);
    path('M0-24 L0-8 Q-20 12-29-8 M0-8 Q20 12 29-8',null,2.5);
    path('M-56 62 L-64 66 M53 66 L62 61 M-70 118 L-52 122 M50 122 L67 118',null,2);
    heart(102,45,.75);ctx.restore();
  }
  function bunnyBurger(x,y,scale=1) {
    ctx.save();ctx.translate(x,y);ctx.scale(scale,scale);
    path('M-53-86 C-96-198-66-267-29-225 Q-2-193-9-94 M23-95 C10-191 39-254 69-238 Q103-218 77-158 L51-78',pink,4);
    path('M-45-111 C-76-195-59-232-45-212 Q-27-175-27-114 M41-113 Q30-195 58-218 Q80-227 61-163 L48-119',ink,2.5);
    path('M-104 55 C-108-56-64-113 7-110 Q102-117 112-20 L113 69 Q-4 111-104 55Z',pink,4);
    dot(-41,-38,4.5);path('M35-47 L57-35 35-28',null,3);
    path('M-5-16 Q3-24 12-13 L7-2 Q-3 1-5-16Z',null,2);
    path('M3-3 Q-5 17-19 11 M3-3 Q11 14 21 7 M-6 7 Q-8 27 5 20',null,2);
    path('M-105 49 Q-77 39-49 53 T8 53 T65 52 T113 54 L113 81 Q87 91 66 78 Q40 94 10 81 Q-17 97-42 83 Q-73 91-102 74Z',ink,3);
    path('M-101 87 Q-74 101-47 91 L-21 104 6 94 31 105 61 94 84 102 111 91 L108 119 Q3 147-97 118Z',pink,3);
    path('M-99 120 Q-71 113-44 126 T14 127 T74 126 L108 118 L106 139 Q0 166-95 140Z',ink,3);
    path('M-94 147 Q-9 171 104 148 Q81 203-7 194 Q-79 193-94 147Z',pink,4);
    path('M-77 176 Q-13 193 76 178',null,2);heart(131,74,.7);ctx.restore();
  }
  function smallRabbit(x,y,scale=1) {
    ctx.save();ctx.translate(x,y);ctx.scale(scale,scale);
    path('M-37-43 Q-52-107-22-108 Q-2-104-12-48 M17-48 Q32-104 58-83 Q71-65 39-34',pink,3);
    path('M-69 55 Q-90-7-40-40 Q12-79 63-26 Q84-3 81 55Z',pink,3);
    dot(-31,0,4);dot(28,-2,4);path('M-8 20 Q0 5 8 20 Q0 29-8 20Z M0 25 Q-5 38-14 33 M0 25 Q7 36 16 30',null,2.1);ctx.restore();
  }
  // Cyan angular robots occupy the other side of the English can.
  function robots(x,y) {
    ctx.save();ctx.translate(x,y);
    path('M-147-166 L87-176 153 1330 -125 1330Z',blue,3);
    path('M-121-104 L-40-166 19-93 101-146 118-39 28 22 -110-13Z',blue,5);
    path('M-101-83 L-48-134 -4-73 67-112 84-32 26-3 -89-30Z',blue,3);
    path('M-86-72 L-52-46 M-82-45 L-51-74 M29-74 L58-59 M42-82 L44-50 M-55-16 L-50 17 2 38 67-1',null,3);
    path('M-47 19 L-2 64 40 35 M-27 40 L-16 30 M-16 51 L-6 40 M-6 59 L4 48',null,2.5);
    path('M-106 79 L34 51 113 138 70 262 -102 228 -133 143Z',blue,5);
    path('M-88 123 Q-37 87-3 129 Q-48 158-88 123Z M25 120 L82 130 40 157Z',pink,3);
    path('M-91 191 Q-18 112 74 189 L57 233 -74 218Z',ink,3);
    for(let i=0;i<8;i++)path(`M${-65+i*16} 195 L${-59+i*15} 214`,null,2,blue);
    path('M-128 290 L23 234 140 349 108 680 -123 652Z',blue,5);
    path('M-128 290 L12 315 23 234 M12 315 L140 349 M-110 377 L130 394 M-125 635 L101 663',null,6);
    path('M-105 405 Q-56 421-14 451 Q-73 483-105 405Z M35 448 L118 422 Q85 487 35 448Z',pink,3);
    path('M-109 507 L113 523 111 601 -107 586Z',blue,4);
    path('M-107 543 L110 559',null,3);
    for(let i=1;i<13;i++)path(`M${-110+i*17} ${507+i*1.3} L${-108+i*17} ${586+i*1.2}`,null,2.2);
    path('M-89 670 L60 693 111 826 48 945 -111 897 -138 791Z',blue,5);
    path('M-98 742 L61 770 M-119 804 L96 830 M-77 863 L57 885 M-40 712 L-73 894 M29 725 L14 920',null,4);
    oval(-72,781,12,14,ink,2);oval(52,809,12,14,ink,2);
    path('M-99 998 L23 922 132 1014 118 1210 -109 1227 -139 1093Z',blue,5);
    path('M-106 1024 L24 970 111 1037 -14 1101Z',ink,3);
    path('M-98 1101 L-63 1128 -100 1176 M19 1115 L68 1118 96 1172 50 1190Z',pink,3);
    for(let i=0;i<44;i++) {
      const xx=-108+(i*43%195), yy=-130+(i*97%1350);
      if(i%3===0)path(`M${xx} ${yy} l7 -4 m-1 11 l5 -2`,null,1.2);else dot(xx,yy,1.4);
    }
    ctx.restore();
  }
  // The back uses the English Nutrition Facts layout from the supplied package.
  ctx.fillStyle=ink;ctx.fillRect(706,159,655,1318);
  ctx.fillStyle=pink;ctx.fillRect(793,215,486,1168);
  ctx.fillStyle=ink;ctx.textAlign='left';ctx.font='900 52px Arial, sans-serif';ctx.fillText('Nutrition Facts',803,264,466);
  ctx.font='24px Arial, sans-serif';ctx.fillText('Serving size',805,307);ctx.textAlign='right';ctx.fillText('1 can',1265,307);
  ctx.fillRect(802,318,466,9);ctx.textAlign='left';ctx.font='16px Arial, sans-serif';ctx.fillText('Amount per serving',805,349);
  ctx.font='bold 35px Arial, sans-serif';ctx.fillText('Calories',805,389);ctx.textAlign='right';ctx.font='bold 45px Arial, sans-serif';ctx.fillText('10',1263,389);
  ctx.fillRect(802,402,466,8);ctx.font='16px Arial, sans-serif';ctx.fillText('% Daily Value*',1265,437);
  const nutrients=[['Total Fat 0g','0%'],['Sodium 390mg','17%'],['Total Carbohydrate 6g','2%'],['Total Sugars 0g',''],['Includes 0g Added Sugars','0%'],['Erythritol 2g',''],['Protein 0g',''],['Niacin (Vit. B3)','250%'],['Vitamin B6','240%'],['Vitamin B12','490%'],['Pantothenic Acid (Vit. B5)','400%']];
  ctx.font='21px Arial, sans-serif';
  for(let i=0;i<nutrients.length;i++) {
    const yy=468+i*35;ctx.fillRect(802,yy-25,466,i===7?5:1.5);ctx.textAlign='left';ctx.fillText(nutrients[i][0],807+(i===3||i===4?15:0),yy,365);ctx.textAlign='right';ctx.fillText(nutrients[i][1],1264,yy);
  }
  ctx.textAlign='left';ctx.font='15px Arial, sans-serif';
  const finePrint=[
    '* The % Daily Value tells you how much a nutrient',
    'in a serving of food contributes to a daily diet.',
    '2,000 calories a day is used for general nutrition advice.',
    'INGREDIENTS: CARBONATED WATER, CITRIC ACID,',
    'ERYTHRITOL, TAURINE, SODIUM CITRATE, NATURAL',
    'FLAVORS, PANAX GINSENG EXTRACT, CAFFEINE,',
    'SUCRALOSE, L-CARNITINE L-TARTRATE, NIACINAMIDE.',
    'CONTAINS CAFFEINE. CONSUME RESPONSIBLY.',
    'NOT RECOMMENDED FOR CHILDREN, PEOPLE SENSITIVE',
    'TO CAFFEINE, PREGNANT WOMEN OR WOMEN NURSING.',
    'MONSTER ENERGY COMPANY · CORONA, CA 92879 USA',
    'MONSTERENERGY.COM · © MONSTER ENERGY COMPANY',
  ];
  finePrint.forEach((line,i)=>ctx.fillText(line,807,877+i*27,455));
  ctx.font='32px Impact, "Arial Narrow", sans-serif';ctx.fillText('CA CRV  CT HI ME MA NY IA',805,1240,456);
  ctx.font='21px Arial, sans-serif';ctx.fillText('MI 5¢  OR 10¢  VT 5¢',805,1280,456);
  ctx.font='18px Arial, sans-serif';ctx.fillText('ZERO SUGAR · ENERGY DRINK',805,1320,456);
  // A barcode and narrow story column fill the reverse-left quarter.
  ctx.fillStyle='#edd5e2';ctx.fillRect(1364,1080,156,338);ctx.fillStyle=ink;
  for(let i=0,x=1373;x<1510;i++){const w=1+i*7%3;ctx.fillRect(x,1092,w,280);x+=w+2+i%2;}
  ctx.font='13px Arial, sans-serif';ctx.textAlign='center';ctx.fillText('0 70847 89720 4',1442,1400,146);
  ctx.textAlign='left';ctx.fillStyle=pale;ctx.font='22px Arial, sans-serif';
  const story=['ULTRA FANTASY','RUBY RED','Welcome to your','fantasy. A fresh','ruby red twist,','a smooth taste,','zero sugar.','MONSTER','ENERGY'];
  story.forEach((line,i)=>ctx.fillText(line,1432,270+i*42,180));
  // Authored, angular lettering avoids substituting an unrelated system display font.
  function wordmark(x, y) {
    // O follows the official flat black contour; its ring and stem must not look lowercase.
    const glyphs = [
      [62, 'M0 7L13 0 32 44 47 3 61 8 58 88 48 82 47 29 34 62 27 60 13 26 14 88 4 84Z'],
      [57, 'M1,9.778 L3.103,9.778 L5.207,3.259 L26.241,3.259 L26.241,-13.037 L24.138,-13.037 L24.138,-16.296 L32.552,-16.296 L32.552,3.259 L38.862,3.259 L38.862,6.519 L47.276,3.259 L47.276,6.519 L55.69,9.778 L51.483,52.148 L49.379,52.148 L47.276,58.667 L43.069,58.667 L43.069,61.926 L36.759,61.926 L36.759,65.185 L30.448,71.704 L30.448,74.963 L32.552,74.963 L32.552,88 L30.448,88 L30.448,91.259 L26.241,91.259 L26.241,88 L24.138,88 L26.241,71.704 L22.034,71.704 L17.828,61.926 L13.621,61.926 L13.621,58.667 L7.31,52.148 L5.207,35.852 L3.103,35.852 L3.103,22.815 L1,22.815Z M11.517,13.037 L13.621,35.852 L15.724,35.852 L15.724,42.37 L24.138,52.148 L24.138,22.815 L26.241,22.815 L26.241,9.778Z M30.448,19.556 L30.448,58.667 L34.655,58.667 L34.655,55.407 L38.862,55.407 L38.862,52.148 L43.069,48.889 L43.069,42.37 L45.172,42.37 L45.172,16.296 L43.069,16.296 L43.069,13.037 L32.552,9.778 L32.552,19.556Z'],
      [60, 'M3 89L7 0 17 7 47 62 45 8 55 3 56 87 46 80 17 29 14 84Z'],
      [58, 'M51 9L35 17 14 15 8 31 40 38 53 51 45 78 22 88 3 75 8 65 23 75 38 69 40 55 10 48 0 35 7 8 28 4 40 8Z'],
      [59, 'M0 12L23 4 46 10 59 2 54 20 36 19 33 84 22 90 23 19 5 25Z'],
      [51, 'M7 10L43 3 49 11 19 22 19 37 40 34 43 44 18 48 16 73 45 65 49 77 6 88 5 28 0 22Z'],
      [59, 'M6 4L32 8 50 20 48 40 32 52 58 80 46 87 21 56 17 54 15 88 4 82ZM18 19L18 42 29 41 38 34 38 24 28 19Z'],
    ];
    ctx.save(); ctx.translate(x - 370, y); ctx.scale(1.75, 1.12); ctx.fillStyle = ink;
    for (const [width, d] of glyphs) { const glyph=new Path2D(d); ctx.strokeStyle='#ddd6d9';ctx.lineWidth=3.5;ctx.stroke(glyph);ctx.fill(glyph,'evenodd');ctx.translate(width+3,0); }
    ctx.restore();
  }
  for (const x of [0,2048]) {
    ctx.save();ctx.translate(x,0);
    // The visible decorative strips stay separate: rounded pink figures at left, blue robots at right.
    robots(420,330);
    path('M-571 173 L-296 177 -307 489 -290 723 -308 1051 -295 1471 -571 1471Z',ink,2);
    // Pink scratches break up the black character field like the printed reference.
    for(let i=0;i<84;i++) {
      const xx=-558+i*37%245, yy=185+i*113%1268;
      path(`M${xx} ${yy} l${3+i%5} ${-2-i%4} m-2 7 l4 -1`,null,1.15,pink);
    }
    path('M-308 189 Q-329 428-302 629 T-313 1060 L-299 1454',null,2,pink);
    flower(-402,241,49,6);flower(-330,312,35,5);flower(-458,347,29,6);
    bear(-401,474,.91);
    bunnyBurger(-389,837,.89);
    flower(-431,1134,44,7);flower(-340,1201,27,6);
    smallRabbit(-390,1400,1.20);
    heart(-303,617,.68);heart(-463,1053,.69);heart(-336,1292,.57);
    for(let i=0;i<44;i++) {
      const xx=-515+i*73%214, yy=189+i*113%1260;
      if(i%3===0)path(`M${xx} ${yy} q-8-8-10 1 q-3 8 7 12 q11-3 10-11`,null,1.1);
      else {dot(xx,yy,1.1);dot(xx+6,yy+3,1);}
    }
    // The original flat claw remains uniformly scaled; the cylinder supplies curvature once.
    ctx.save();ctx.translate(-63*5.8,255-22*5.8);ctx.scale(5.8,5.8);
    ctx.fillStyle='#cbd0cd';ctx.fill(claw);ctx.strokeStyle=ink;ctx.lineWidth=1.15;ctx.stroke(claw);ctx.restore();
    wordmark(0,1000);
    ctx.textAlign='center';ctx.fillStyle='#f5e5ec';ctx.font='600 39px Arial, sans-serif';ctx.fillText('E  N  E  R  G  Y',0,1173,416);
    ctx.fillStyle=ink;ctx.font='900 43px "Arial Black", Arial, sans-serif';ctx.fillText('ULTRA FANTASY',0,1271,465);
    ctx.font='900 46px "Arial Black", Arial, sans-serif';ctx.fillText('RUBY RED',0,1337,377);
    ctx.font='16px Arial, sans-serif';ctx.fillText('™',197,1298);
    // The English front has a compact energy-drink label and a white zero-sugar side badge.
    ctx.save();ctx.translate(-415,1428);ctx.rotate(-.025);ctx.fillStyle=pale;ctx.fillRect(-75,-25,149,42);
    ctx.fillStyle=ink;ctx.font='25px Impact, "Arial Narrow", sans-serif';ctx.fillText('ENERGY DRINK',0,7,140);ctx.restore();
    ctx.save();ctx.translate(426,1330);ctx.rotate(.10);
    ctx.beginPath();ctx.roundRect(-52,-88,104,176,18);ctx.fillStyle='#f4eeee';ctx.fill();ctx.lineWidth=3;ctx.strokeStyle=ink;ctx.stroke();
    ctx.fillStyle=ink;ctx.font='72px Impact, "Arial Narrow", sans-serif';ctx.fillText('0',0,-15);
    ctx.font='bold 19px Arial, sans-serif';ctx.fillText('SUGAR',0,16);ctx.fillText('PER CAN',0,43);ctx.restore();
    ctx.restore();
  }
  // Pink shoulder with English type; black distressed ink sits below it, not over it.
  ctx.fillStyle='#ed61ac';ctx.fillRect(0,0,2048,153);
  ctx.fillStyle=ink;ctx.fillRect(0,151,2048,35);
  ctx.beginPath();ctx.moveTo(0,181);
  for(let x=0;x<=2048;x+=8) {
    const frontDistance=Math.min(x,2048-x);
    ctx.lineTo(x,184+(frontDistance>170?17:5)+(x*17%23));
  }
  ctx.lineTo(2048,169);ctx.lineTo(0,169);ctx.closePath();ctx.fill();
  for(let i=0;i<1080;i++) {
    const x=i*89%2048,y=181+i*23%74;
    const frontDistance=Math.min(x,2048-x);
    if(frontDistance>170||i%5===0)ctx.fillRect(x,y,1+i%6,2+i*7%17);
  }
  ctx.textAlign='center';ctx.fillStyle=ink;ctx.font='italic 500 45px "Arial Narrow", Arial, sans-serif';
  for(const x of [0,2048])ctx.fillText('Z E R O  S U G A R',x,105,535);
  ctx.font='italic 500 31px "Arial Narrow", Arial, sans-serif';
  ctx.fillText('L - C A R N I T I N E',1024,103,510);
  ctx.fillText('+  T A U R I N E  +',510,102,380);ctx.fillText('+  Z E R O  S U G A R  +',1540,102,420);
  // Fine repeatable print grain, much smaller than the illustration linework.
  ctx.globalAlpha=.07;ctx.fillStyle='#ffd1e9';
  for(let i=0;i<22000;i++)ctx.fillRect(i*193%2048,180+i*229%1324,.7+i%2*.4,.7+i*3%2*.4);
  ctx.globalAlpha=1;
  const map=new CanvasTexture(canvas);map.colorSpace=SRGBColorSpace;map.anisotropy=4;return map;
}
