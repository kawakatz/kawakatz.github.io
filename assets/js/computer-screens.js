import * as THREE from 'three';
import { drawMacDock, getMacDockItemRect, MAC_DOCK_ICON_KEYS } from './mac-dock.js';

// Offline app artwork combines supplied RDP screenshots with an original, inert review storyboard.
// No tool execution, network requests or executable payloads. Motion uses the caller's paused clock.
const artworkIcons = new WeakMap();
const UI = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
const MONO = 'Menlo, Consolas, monospace';
const rdpTime = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', hour: 'numeric', minute: '2-digit', hour12: true });
const rdpDate = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'numeric', day: 'numeric' });
const macDate = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', weekday: 'short', month: 'short', day: 'numeric' });
const macClock = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const fill = (c,x,y,w,h,color) => { c.fillStyle=color; c.fillRect(x,y,w,h); };
const text = (c,value,x,y,color='#333942',size=11,weight=400,font=UI) => { c.fillStyle=color;c.font=`${weight} ${size}px ${font}`;c.fillText(value,x,y); };
const round = (c,x,y,w,h,r,color) => { c.fillStyle=color;c.beginPath();c.roundRect(x,y,w,h,r);c.fill(); };
const line = (c,points,color='#657080',width=1) => { c.strokeStyle=color;c.lineWidth=width;c.beginPath();points.forEach(([x,y],i)=>i?c.lineTo(x,y):c.moveTo(x,y));c.stroke(); };
const circle = (c,x,y,r,color) => {c.fillStyle=color;c.beginPath();c.arc(x,y,r,0,Math.PI*2);c.fill();};
const smooth = value => { const t=Math.max(0,Math.min(1,value));return t*t*(3-2*t); };
const travel = (t,start,end) => smooth((t-start)/(end-start));
function canvas(w,h,paint,scale,icons) {
  const image=document.createElement('canvas');image.width=Math.round(w*scale);image.height=Math.round(h*scale);
  const c=image.getContext('2d');c.scale(scale,scale);c.lineJoin='round';c.lineCap='round';
  if(icons)artworkIcons.set(c,icons);
  if(paint)paint(c);return image;
}
// Cached text is rasterized at its final scale, then copied one source pixel to one destination pixel.
function paste(c,image,x,y,scale) {
  const {a,d,e,f}=c.getTransform();
  c.save();c.setTransform(1,0,0,1,Math.round(x*a+e),Math.round(y*d+f));c.drawImage(image,0,0);c.restore();
}
function icon(c,name,x,y,size=14,color='#616b78') {
  c.save();c.translate(x,y);c.scale(size/16,size/16);
  const image=name==='vmware'?null:artworkIcons.get(c)?.[name];
  if(image){c.drawImage(image,0,0,16,16);c.restore();return;}
  if(name==='codex')name='spark';
  const paths={ close:[[[4,4],[12,12]],[[12,4],[4,12]]],plus:[[[8,3],[8,13]],[[3,8],[13,8]]],minus:[[[3,8],[13,8]]],
    back:[[[9,3],[4,8],[9,13]],[[4,8],[14,8]]],next:[[[7,3],[12,8],[7,13]],[[2,8],[12,8]]],up:[[[3,7],[8,2],[13,7]],[[8,2],[8,14]]],
    chevron:[[[5,6],[8,9],[11,6]]],expand:[[[3,3],[13,3],[13,13],[3,13],[3,3]]],check:[[[3,8],[6,11],[13,4]]],
    menu:[[[3,4],[13,4]],[[3,8],[13,8]],[[3,12],[13,12]]],copy:[[[6,5],[13,5],[13,13],[6,13],[6,5]],[[10,3],[3,3],[3,10]]],
    sidebar:[[[2,3],[14,3],[14,13],[2,13],[2,3]],[[6,3],[6,13]]],terminal:[[[3,4],[7,8],[3,12]],[[8,12],[13,12]]],
    home:[[[2,7],[8,2],[14,7]],[[4,6],[4,14],[7,14],[7,10],[10,10],[10,14],[12,14],[12,6]]],
    download:[[[8,2],[8,11]],[[4,7],[8,11],[12,7]],[[3,13],[13,13]]],external:[[[9,2],[14,2],[14,7]],[[7,9],[14,2]],[[6,3],[2,3],[2,14],[13,14],[13,10]]],
    play:[[[5,3],[13,8],[5,13],[5,3]]],pause:[[[5,3],[5,13]],[[11,3],[11,13]]],file:[[[4,2],[10,2],[13,5],[13,14],[4,14],[4,2]],[[10,2],[10,5],[13,5]],[[6,8],[11,8]],[[6,11],[11,11]]],
    branch:[[[5,3],[5,13]],[[5,9],[11,6],[11,3]]],grid:[[[2,2],[6,2],[6,6],[2,6],[2,2]],[[10,2],[14,2],[14,6],[10,6],[10,2]],[[2,10],[6,10],[6,14],[2,14],[2,10]],[[10,10],[14,10],[14,14],[10,14],[10,10]]],
  };
  if(name==='vscode'){
    c.fillStyle='#24a8ed';c.beginPath();[[12,1],[6,6],[2.5,3],[.5,4.5],[4.5,8],[.5,11.5],[2.5,13],[6,10],[12,15],[16,13.3],[16,2.7]].forEach(([x,y],i)=>i?c.lineTo(x,y):c.moveTo(x,y));c.closePath();c.fill();
    c.fillStyle='#0876bd';c.beginPath();[[12,1],[12,15],[16,13.3],[16,2.7]].forEach(([x,y],i)=>i?c.lineTo(x,y):c.moveTo(x,y));c.closePath();c.fill();
  }
  else if(name==='vmware'){
    c.lineWidth=1.5;c.strokeStyle='#f2ae43';c.beginPath();c.roundRect(1,1,9,9,1.8);c.stroke();c.strokeStyle='#4f9bc7';c.beginPath();c.roundRect(6,6,9,9,1.8);c.stroke();
  }
  else if(name==='chrome'){
    circle(c,8,8,7.8,'#e95d50');
    for(const [start,end,tint] of [[0,Math.PI*2/3,'#e9c747'],[Math.PI*2/3,Math.PI*4/3,'#51a367']]){c.beginPath();c.moveTo(8,8);c.arc(8,8,7.8,start,end);c.closePath();c.fillStyle=tint;c.fill();}
    circle(c,8,8,3.9,'#e4eff1');circle(c,8,8,3.15,'#4598d8');
  }
  else if(name==='edge'){
    circle(c,8,8,7.7,'#188ccb');c.fillStyle='#2fc7b6';c.beginPath();c.moveTo(.7,9);c.bezierCurveTo(-1,0,12,-3,15,5);c.bezierCurveTo(8,1,3,5,3,8);c.closePath();c.fill();
    c.fillStyle='#164ba3';c.beginPath();c.moveTo(3,8);c.bezierCurveTo(3,16,12,16,15,10);c.bezierCurveTo(10,13,5,12,3,8);c.fill();circle(c,9,7.5,3,'#d7f6eb');
  }
  else if(name==='system'){
    round(c,1,1,14,14,3,'#354964');line(c,[[2,11],[5,11],[6,5],[8,13],[10,7],[12,7],[13,3],[14,3]],'#98deba',1.2);
  }
  else if(name==='ninja'){
    round(c,1,1,14,14,3,'#332326');line(c,[[4,12],[4,4],[11,12],[11,4]],'#ef5260',2);line(c,[[2,8],[14,8]],'#d8bcc3',.7);
  }
  else if(name==='trash'||name==='trash-win'){
    round(c,4,3,9,12,1.2,'#dce7eb');fill(c,3,2,11,2,'#f7fbff');fill(c,6,1,5,1,'#c2d5dc');line(c,[[6,6],[5,9],[8,11],[10,8],[8,5],[6,6]],'#5c9a90',.9);
  }
  else if(name==='shield'){line(c,[[8,1],[14,4],[13,10],[11,13],[8,15],[5,13],[3,10],[2,4],[8,1]],color,1.2);line(c,[[8,4],[8,9]],color,1.2);circle(c,8,12,.7,color);}
  else if(name==='mic'){c.strokeStyle=color;c.lineWidth=1.2;c.beginPath();c.roundRect(5,1,6,9,3);c.stroke();c.beginPath();c.arc(8,7,5,0,Math.PI);c.stroke();line(c,[[8,12],[8,15]],color,1.2);}
  else if(name==='new-chat'){line(c,[[8,3],[3,3],[3,13],[13,13],[13,8]],color,1.2);line(c,[[7,9],[8,6],[13,1],[15,3],[10,8],[7,9]],color,1.2);}
  else if(name==='search'){c.strokeStyle=color;c.lineWidth=1.3;c.beginPath();c.arc(7,7,4.2,0,Math.PI*2);c.stroke();line(c,[[10,10],[14,14]],color,1.3);}
  else if(name==='folder'||name==='folder-win'||name==='folder-generic'){fill(c,1,4,7,3,'#deb35b');round(c,1,6,14,8,1.2,'#e8bd61');fill(c,2,7,12,1,'#f6d58b');}
  else if(name==='dots'){for(let i=0;i<3;i++)circle(c,3+i*5,8,1,color);}
  else if(name==='windows'){for(let j=0;j<2;j++)for(let i=0;i<2;i++)fill(c,1+i*8,1+j*8,6,6,color);}
  else if(name==='refresh'){c.strokeStyle=color;c.lineWidth=1.2;c.beginPath();c.arc(8,8,5,Math.PI*.1,Math.PI*1.75);c.stroke();line(c,[[12,2],[12,6],[8,6]],color,1.2);}
  else if(name==='spark'){for(let i=0;i<6;i++){const a=i*Math.PI/3;line(c,[[8+Math.cos(a)*3,8+Math.sin(a)*3],[8+Math.cos(a)*6,8+Math.sin(a)*6]],color,1.7);}}
  else for(const path of paths[name]||paths.file)line(c,path,color,1.2);
  c.restore();
}
function panel(c,x,y,w,h,paint,color='#f8f9fb',radius=8){
  c.save();c.shadowColor='rgba(9,15,29,.28)';c.shadowBlur=18;c.shadowOffsetY=7;round(c,x,y,w,h,radius,color);c.restore();
  c.save();c.beginPath();c.roundRect(x,y,w,h,radius);c.clip();paint();c.restore();
}

// Each window is authored at its native screenshot scale; only vector drawing is transformed.
const desktopWidth=6400/3,desktopHeight=600;
const researchDock={x:1087.5-1225*18/41,y:562,w:1225*36/41,h:36};
const desktopFocus=[[0,'Codex'],[3.5,'Ghidra'],[11,'Microsoft Edge'],[17.05,'Caido'],[17.8,'Windows App'],[21.85,'Codex'],[22.05,'Windows App'],[22.9,'Ghidra'],[23.45,'Caido'],[26.9,'Microsoft Edge'],[28.9,'Codex']];
const reviewProgress=[
  [3.05,'text',['I’ll review messages.kawakatz.com and follow the message handling code in Ghidra.']],
  [3.6,'status',['Researching the application and project context'],6.2,'search'],
  [4.3,'agents',[['Atlas','Lyra'],'Message handlers and desktop review updated']],
  [5.5,'text',['The message flow is mapped. I’m checking how the remote session presents each result.']],
  [6.2,'status',['Reading references and clarifying function names'],9.8,'edit'],
  [7.7,'agents',[['Atlas'],'Message handler review updated']],
  [8.8,'text',['The function and variable names are clearer now. I’ll compare the browser response with the desktop state.']],
  [9.8,'status',['Inspecting the message view'],13.5,'computer'],
  [11.2,'agents',[['Lyra','Nova'],'Browser and response review updated']],
  [12.6,'text',['The browser and remote session are responding consistently. I’m checking the visible result before summarizing.']],
  [13.5,'status',['Tracing message delivery across the open windows'],15.6,'read'],
  [14.8,'text',['The notification is ready for a final check. I’m validating the result in the remote desktop.']],
  [15.6,'status',['Validating the Replay response and desktop state'],18.55,'terminal'],
  [18,'result',['RCE confirmed.']],
];
const reviewResult=[
  [18.65,'result',['RCE confirmed.','Untrusted message data reached a privileged execution path.','Impact: remote code execution in the message service.','Under the program guidelines, this vulnerability qualifies for the $10,000 reward tier.','Fix: validate message fields and isolate privileged operations.'],20.35],
  [20.45,'actions',[]],
];
const cleanupProgress=[
  [22,'text',['Sure. I’ll close the temporary windows and clear the review activity from Replay and HTTP History.']],
  [22.25,'status',['Closing Calculator and dismissing the notification'],24.5,'computer'],
  [24.5,'status',['Clearing Replay sessions and HTTP History'],26.6,'edit'],
  [26.6,'status',['Checking the desktop state'],27.6,'computer'],
  [26.8,'text',['Replay and HTTP History are clear.']],
];
const cleanupResult=[
  [27.7,'result',['Cleaned up.','Calculator and the notification are closed.','Replay and HTTP History are clear.'],28.5],
  [28.6,'actions',[]],
];
const codexSequence=[...reviewProgress,[18.55],...reviewResult,[21.85],...cleanupProgress,[27.6],...cleanupResult,[28.7,'navigation',[],29.4],[28.9],[30]];
const operationRanges=[[3.5,8.3],[8.3,10.3],[10.3,12.65],[12.65,16.7],[16.7,18.7],[21.85,23.7],[23.7,26.4],[26.4,27.6],[27.6,29.3]];
// The final navigation is a silent new-chat click after the completed reply, not another status row.
const operationStages=codexSequence.filter(([,kind])=>kind==='status'||kind==='navigation').map(([start],i)=>({start,end:codexSequence.find(([at])=>at>start)[0],from:operationRanges[i][0],to:operationRanges[i][1]}));
export function researchOperationTime(t){
  const stage=operationStages.findLast(({start})=>t>=start);
  return stage?stage.from+(stage.to-stage.from)*Math.min(1,(t-stage.start)/(stage.end-stage.start)):0;
}
// Stretch the shared storyboard between outputs: finish each reply or investigation before the next row.
const basePlayback=t=>t<=3?t:3+(t-3)*87/27;
const researchTimeline=[[0],[3],...codexSequence].reduce((timeline,row,i,rows)=>{
  if(!i)return [[0,0]];
  const previous=rows[i-1],gap=basePlayback(row[0])-basePlayback(previous[0]);
  const hold=['text','result'].includes(previous[1])?previous[2].join('').length/17+.35:['status','navigation'].includes(previous[1])?basePlayback(previous[3])-basePlayback(previous[0]):0;
  timeline.push([row[0],Math.ceil((timeline.at(-1)[1]+Math.max(gap,hold))*30-1e-7)/30]);
  return timeline;
},[]);
export function researchPlayback(t){
  const i=researchTimeline.findIndex(([at])=>at>t),b=researchTimeline[i<0?researchTimeline.length-1:i],a=researchTimeline[Math.max(0,(i<0?researchTimeline.length-1:i)-1)];
  return a[1]+(t-a[0])/(b[0]-a[0])*(b[1]-a[1]);
}
function researchTime(bucket){
  const seconds=(bucket%Math.round(researchTimeline.at(-1)[1]*30))/30;
  const i=researchTimeline.findIndex(([,at])=>at>seconds),[a,b]=[researchTimeline[Math.max(0,i-1)],researchTimeline[i]];
  return a[0]+(seconds-a[1])/(b[1]-a[1])*(b[0]-a[0]);
}
const appLayout={
  rdp:{x:19,y:21,w:636,h:636*932/1529,native:1529},
  ghidra:{x:202,y:143,w:558,h:419,native:1400},
  codex:{x:775,y:14,w:558,h:548,native:1280},
  edge:{x:1660,y:16,w:455,h:296,native:1280},
  caido:{x:1343,y:108,w:748,h:432,native:1536},
};
const screenPoint=(name,x,y)=>{const app=appLayout[name],s=app.w/app.native;return [app.x+x*s,app.y+y*s];};
const sampleFunctions=[
  {raw:'FUN_140001120',name:'read_message',address:0x140001120,calls:['format_preview'],code:[
    'Message read_message(const Inbox *inbox)','{','    Message message = {0};','    if (inbox == NULL) {','        return message;','    }','','    message.id = inbox->selected_id;','    message.author = "Desk preview";','    message.text = "Hello from the desk.";','    message.unread = false;','','    return message;','}']},
  {raw:'FUN_140001360',name:'format_preview',address:0x140001360,calls:['format_badge'],code:[
    'Preview format_preview(const Message *message)','{','    Preview preview = {0};','    if (message == NULL) {','        return preview;','    }','','    preview.title = "New message";','    preview.subtitle = message->author;','    preview.body = message->text;','    preview.icon = ICON_MESSAGE;','    preview.visible = true;','','    return preview;','}']},
  {raw:'FUN_140001590',name:'render_card',address:0x140001590,calls:['draw_panel','draw_label'],code:[
    'void render_card(const Preview *preview)','{','    if (preview == NULL || !preview->visible) {','        return;','    }','','    draw_panel(PANEL_MESSAGE);','    draw_label(preview->title);','    draw_label(preview->subtitle);','    draw_label(preview->body);','','    if (preview->icon == ICON_CALCULATOR) {','        draw_calculator_card();','    }','}']},
  {raw:'FUN_140001740',name:'format_badge',address:0x140001740,calls:['draw_label'],code:[
    'Badge format_badge(const Message *message)','{','    Badge badge = {0};','    if (message == NULL) {','        return badge;','    }','','    badge.text = "Read";','    badge.color = COLOR_SECONDARY;','    badge.visible = true;','','    if (message->unread) {','        badge.text = "New";','        badge.color = COLOR_ACCENT;','    }','','    if (message->pinned) {','        badge.icon = ICON_PIN;','        badge.tooltip = "Pinned message";','    }','','    badge.padding = 8;','    badge.radius = 4;','    badge.align = ALIGN_RIGHT;','','    return badge;','}']},
  {raw:'FUN_140001920',name:'present_message',address:0x140001920,calls:['read_message','format_preview','format_badge','render_card'],code:[
    'void present_message(const Inbox *inbox)','{','    if (inbox == NULL) {','        return;','    }','','    // Build the visible message card.','    Message message = read_message(inbox);','    Preview preview = format_preview(&message);','    Badge badge = format_badge(&message);','','    Frame frame = {0};','    frame.width = 420;','    frame.padding = 16;','    frame.spacing = 12;','    frame.background = COLOR_PANEL;','','    begin_frame(&frame);','    draw_avatar(message.author);','    draw_label(preview.subtitle);','    draw_separator();','','    if (preview.visible) {','        render_card(&preview);','    }','','    // Keep the status in the trailing column.','    begin_row(ALIGN_RIGHT);','    if (badge.visible) {','        draw_badge(&badge);','    }','    end_row();','','    draw_separator();','    draw_timestamp(message.created_at);','    draw_button("Reply");','    draw_button("Mark as read");','','    end_frame();','}']},
];
function appFrame(c,name,paint){
  const {x,y,w,h,native}=appLayout[name],scale=w/native;
  panel(c,x,y,w,h,()=>{c.save();c.translate(x,y);c.scale(scale,scale);paint(c,native,h/scale);c.restore();},name==='ghidra'?'#eee':'#232629',5);
}
function nativeTraffic(c,x=16,y=15){['#ff6058','#febd2f','#29c840'].forEach((color,i)=>circle(c,x+i*22,y,6,color));}
function divider(c,x,y,w,color='#d0d0d0'){fill(c,x,y,w,1,color);}
function nativeText(c,value,x,y,color='#333',size=13,weight=400,font=UI){text(c,value,x,y,color,size,weight,font);}
function syntax(c,value,x,y,size=13){
  const tokens=value.match(/\/\/.*$|"[^"\n]*"|\b(?:void|const|return|if|false|true|NULL|bool)\b|\b\d+\b|\b\w+(?=\()|[^\w"\d]+|\w+/g)||[];
  for(const token of tokens){const color=token.startsWith('//')?'#909090':token.startsWith('"')?'#008000':/^(void|const|return|if|bool)$/.test(token)?'#0000ff':/^(false|true|NULL|\d+)$/.test(token)?'#008080':/^\w+$/.test(token)&&value.includes(token+'(')?'#bb00bb':'#333';nativeText(c,token,x,y,color,size,400,MONO);x+=c.measureText(token).width;}
}
function wallpaper(c,x,y,w,h,image=null){
  if(image){const scale=Math.max(w/image.width,h/image.height),sw=w/scale,sh=h/scale;c.drawImage(image,(image.width-sw)/2,(image.height-sh)/2,sw,sh,x,y,w,h);return;}
  const gradient=c.createLinearGradient(0,y,0,y+h);gradient.addColorStop(0,'#247dab');gradient.addColorStop(.48,'#9cc1c5');gradient.addColorStop(.5,'#2e94ad');gradient.addColorStop(1,'#164b68');fill(c,x,y,w,h,gradient);
}
function macMenu(c,image,date,app){
  const f=desktopWidth/5120,capture=image?.width===5120&&image.height===1440;
  if(capture){
    c.drawImage(image,0,0,5120,24,0,0,desktopWidth,24*f);
    c.drawImage(image,390,0,40,24,47*f,0,700*f,24*f);
    c.drawImage(image,4957,0,12,24,4968*f,0,152*f,24*f);
  }else{fill(c,0,0,desktopWidth,24*f,'rgba(33,67,82,.4)');circle(c,26*f,13*f,5*f,'#f0f6f7');}
  text(c,app,55*f,18*f,'#f0f6f7',13*f,600);
  const menuX=55*f+c.measureText(app).width+22*f;
  if(capture)c.drawImage(image,116,0,272,24,menuX,0,272*f,24*f);
  else text(c,'File    Edit    View    Window    Help',menuX,18*f,'#edf5f7',12.5*f);
  const stamp=macDate.format(date).replace(/,/g,'')+' '+macClock.format(date);
  c.save();c.textAlign='right';c.font=`400 ${12.5*f}px ${UI}`;
  const size=12.5*f*Math.min(1,130*f/c.measureText(stamp).width);
  text(c,stamp,5102*f,18*f,'#f0f6f7',size);c.restore();
}
function drawResearch(c,coast){
  if(coast?.width!==5120||coast.height!==1440){wallpaper(c,0,0,desktopWidth,desktopHeight,coast);return;}
  // Crop above the photographed Dock, then cover without stretching the photograph.
  const sourceHeight=1316,sourceWidth=sourceHeight*desktopWidth/desktopHeight;
  c.drawImage(coast,(5120-sourceWidth)/2,24,sourceWidth,sourceHeight,0,0,desktopWidth,desktopHeight);
}
function drawRdp(c,t,assets){appFrame(c,'rdp',(c,w,h)=>{
  if(assets.rdpImages.desktop)c.drawImage(assets.rdpImages.desktop,0,0,w,h);
  else{fill(c,0,0,w,h,'#eee');fill(c,0,0,w,32,'#242729');nativeTraffic(c);nativeText(c,'Windows App',95,21,'#b5b9bd',13);}
  // Replace only the recorded date, keeping the speaker and other tray icons intact.
  fill(c,1444,887,78,41,'#eee');c.save();c.textAlign='right';
  nativeText(c,rdpTime.format(assets.date).replace(/\s/g,' '),1510,904,'#333',11.5,400,'"Segoe UI", Arial, sans-serif');
  nativeText(c,rdpDate.format(assets.date),1510,920,'#333',11.5,400,'"Segoe UI", Arial, sans-serif');c.restore();
  if(t>=17.8&&t<22.55){
    const progress=travel(t,17.8,17.88)*(1-travel(t,22.45,22.55)),x=w-396+(1-progress)*32,y=720;
    c.save();c.globalAlpha=progress;
    c.shadowColor='rgba(18,30,44,.18)';c.shadowBlur=18;c.shadowOffsetY=5;
    round(c,x,y,380,148,9,'#edf3f9');c.shadowColor='transparent';
    c.strokeStyle='#cbd3dc';c.lineWidth=.8;c.stroke();
    round(c,x+16,y+15,17,17,4,'#39c4e9');
    nativeText(c,'Desk Messages',x+43,y+28,'#303840',12.5);
    icon(c,'dots',x+313,y+16,17,'#9099a2');icon(c,'close',x+347,y+16,17,'#9099a2');
    nativeText(c,'Message received',x+16,y+65,'#20262c',15,600);
    nativeText(c,'Hello from the desk.',x+16,y+87,'#59616a',14);
    for(const [label,left] of [['Open',16],['Dismiss',195]]){
      round(c,x+left,y+106,169,27,4,'#f9fbfd');c.strokeStyle='#cdd5de';c.lineWidth=.8;c.stroke();
      c.save();c.textAlign='center';nativeText(c,label,x+left+84.5,y+124,'#30363d',12.5);c.restore();
    }
    c.restore();
  }
  if(t>=18.4&&t<22.15&&assets.rdpImages.calculator){c.save();c.globalAlpha=1-travel(t,22.05,22.15);c.shadowColor='rgba(0,0,0,.2)';c.shadowBlur=18;c.shadowOffsetY=6;c.drawImage(assets.rdpImages.calculator,120,100,322,533);c.restore();}
});}
function paneTitle(c,label,x,y,w,active=false){fill(c,x,y,w,23,active?'#b6c2d1':'#d1d1d1');nativeText(c,label,x+7,y+16,'#222',13,500);icon(c,'expand',x+w-38,y+5,12,'#666');icon(c,'close',x+w-19,y+5,12,'#222');divider(c,x,y+22,w,'#777');}
function ghidraArtwork(c,fn,listing){
  if(listing){
    for(let row=0;row<7;row++){nativeText(c,(fn.address-28+row*4).toString(16),48,18+row*17,'#222',13,400,MONO);nativeText(c,'cc',161,18+row*17,'#00f',13,400,MONO);nativeText(c,'??',257,18+row*17,'#00f',13,400,MONO);nativeText(c,'CCh',317,18+row*17,'#008000',13,400,MONO);}
    nativeText(c,'************************ FUNCTION ************************',196,162,'#888',12,400,MONO);nativeText(c,'undefined '+fn.raw+'()',196,195,'#008080',13,400,MONO);nativeText(c,'assume GS_OFFSET = 0xff00000000',196,212,'#808000',13,400,MONO);nativeText(c,fn.raw,196,246,'#00f',13,600,MONO);
    const asm=[['48 89 5c 24 20','MOV','qword ptr [RSP + 0x20], RBX'],['55','PUSH','RBP'],['48 8b ec','MOV','RBP, RSP'],['48 83 ec 20','SUB','RSP, 0x20'],['48 8b d9','MOV','RBX, RCX'],['48 85 c9','TEST','RCX, RCX'],['74 18','JZ','LAB_140001184'],['48 8b 43 08','MOV','RAX, qword ptr [RBX + 0x8]'],['48 89 45 f0','MOV','qword ptr [RBP - 0x10], RAX'],['48 8d 4d e0','LEA','RCX, [RBP - 0x20]'],['e8 41 00 00 00','CALL','format_preview'],['48 83 c4 20','ADD','RSP, 0x20'],['5d','POP','RBP'],['c3','RET','']];
    for(let repeat=0;repeat<3;repeat++)asm.forEach(([bytes,mnemonic,operand],i)=>{const row=repeat*asm.length+i,y=282+row*17;if(mnemonic==='CALL')operand=fn.calls[repeat%fn.calls.length];if(mnemonic==='JZ')operand='LAB_'+(fn.address+100+repeat*56).toString(16);nativeText(c,(fn.address+row*4).toString(16),48,y,'#111',13,400,MONO);nativeText(c,bytes,161,y,'#00f',13,400,MONO);nativeText(c,mnemonic,305,y,'#00f',13,400,MONO);nativeText(c,operand,374,y,mnemonic==='CALL'?'#c00000':'#008000',13,400,MONO);});
  }else{
    const lines=['',fn.code[0].replace(fn.name,fn.raw),...fn.code.slice(1)];
    lines.forEach((value,i)=>{nativeText(c,String(i+1),3,18+i*17,'#333',12,400,MONO);syntax(c,value,30,18+i*17,13);});
  }
}
function drawRenameDialog(c,fn,local,elapsed,parentWidth,parentHeight){
  const w=local?364:522,h=local?130:266,x=(parentWidth-w)/2,y=(parentHeight-h)/2;
  const oldName=local?'local_18':fn.raw,newName=local?'preview':fn.name,selected=elapsed<.23;
  const value=selected?oldName:newName.slice(0,Math.max(0,Math.floor((elapsed-.23)/.24*newName.length)));
  panel(c,x,y,w,h,()=>{
    c.save();c.translate(x,y);
    const reference=artworkIcons.get(c)?.[local?'ref-ghidra-variable':'ref-ghidra-function'];
    if(reference)c.drawImage(reference,56,38,w,h,0,0,w,h);
    else{fill(c,0,0,w,32,'#23292b');for(const [i,color] of ['#ff6058','#424a4d','#29c840'].entries())circle(c,16+i*23,16,6,color);}
    fill(c,81,4,w-89,24,'#23292b');
    nativeText(c,local?'Rename Local Variable':'Rename Function at '+fn.address.toString(16),84,21,'#aeb6b9',13,600);
    let fieldX=14,fieldY=59,fieldWidth=w-28;
    if(local){
      const label='Rename '+oldName+':';c.font=`400 13px ${UI}`;
      fieldX=Math.max(110,16+c.measureText(label).width);fieldY=43;fieldWidth=w-fieldX-10;
      fill(c,5,40,fieldX-5,25,'#ededed');
      nativeText(c,label,8,57,'#111',13);
    }else nativeText(c,'Enter Name:',14,52,'#111',13);
    round(c,fieldX,fieldY,fieldWidth,21,2,'#fff');c.strokeStyle='#cbd5df';c.lineWidth=1;c.stroke();
    c.save();c.beginPath();c.rect(fieldX+3,fieldY+2,fieldWidth-(local?6:23),17);c.clip();c.font=`400 13px ${UI}`;
    const valueWidth=c.measureText(value).width;
    if(selected)fill(c,fieldX+3,fieldY+2,valueWidth+1,17,'#456589');
    nativeText(c,value,fieldX+4,fieldY+16,selected?'#fff':'#111',13);
    if(!selected)fill(c,fieldX+4+valueWidth,fieldY+3,1,15,'#111');
    c.restore();
    if(reference){c.restore();return;}
    if(!local){
      const stepX=fieldX+fieldWidth-17;
      round(c,stepX,fieldY+1,16,19,4,'#edf1f4');
      line(c,[[stepX+5,fieldY+8],[stepX+8,fieldY+5],[stepX+11,fieldY+8]],'#c1ccd5',1);
      line(c,[[stepX+5,fieldY+12],[stepX+8,fieldY+15],[stepX+11,fieldY+12]],'#c1ccd5',1);
      nativeText(c,'Namespace',14,104,'#111',13);
      round(c,14,110,w-62,22,9,'#f4f4f4');c.strokeStyle='#d4d4d4';c.lineWidth=.8;c.stroke();nativeText(c,'Global',27,126,'#111',13);
      round(c,w-67,113,16,16,4,'#1672e9');line(c,[[w-63,120],[w-59,116],[w-55,120]],'#fff',1);line(c,[[w-63,123],[w-59,127],[w-55,123]],'#fff',1);
      round(c,w-34,112,21,21,6,'#f7f7f7');c.strokeStyle='#d4d4d4';c.stroke();icon(c,'dots',w-31,115,15,'#333');
      c.beginPath();c.rect(9,151,w-18,47);c.strokeStyle='#aaa';c.lineWidth=1;c.stroke();
      fill(c,14,143,74,17,'#ededed');nativeText(c,'Properties',16,158,'#111',13);
      for(const [label,left,disabled] of [['Entry Point',132,false],['Primary',244,true],['Pinned',328,false]]){
        round(c,left,172,15,15,4,'#f2f2f2');c.strokeStyle=disabled?'#e2e2e2':'#d3d3d3';c.lineWidth=.8;c.stroke();
        if(disabled)icon(c,'check',left+1,173,13,'#e4e4e4');
        nativeText(c,label,left+21,184,disabled?'#909090':'#111',13);
      }
    }
    divider(c,0,h-44,w,'#b2b2b2');divider(c,0,h-43,w,'#fff');
    for(const [label,left] of [['OK',w/2-82],['Cancel',w/2+9]]){
      round(c,left,h-30,73,20,6,label==='OK'?(elapsed>.59?'#095dc9':'#166ce6'):'#f7f7f7');
      if(label==='Cancel'){c.strokeStyle='#d4d4d4';c.lineWidth=.8;c.stroke();}
      c.save();c.textAlign='center';nativeText(c,label,left+36.5,h-16,'#080808',13);c.restore();
    }
    c.restore();
  },'#ededed',16);
}
function drawGhidra(c,t,assets){appFrame(c,'ghidra',(c,w,h)=>{
  const reference=artworkIcons.get(c)?.['ref-ghidra'],scale=w/1430;
  fill(c,0,0,w,h,'#ededed');
  if(reference){
    // Extend only the blank lower panels; keep the screenshot's type and toolbar proportions.
    const top=906*scale,bottom=92*scale;
    c.drawImage(reference,56,38,1430,906,0,0,w,top);
    c.drawImage(reference,56,943,1430,1,0,top,w,h-top-bottom);
    c.drawImage(reference,56,944,1430,92,0,h-bottom,w,bottom);
  }
  fill(c,80*scale,3*scale,550*scale,26*scale,'#232b2d');nativeText(c,'CodeBrowser: message_demo.exe',84*scale,22*scale,'#aeb7ba',13,600);
  fill(c,63*scale,132*scale,116*scale,16*scale,'#fff');nativeText(c,'message_demo.exe',64*scale,145*scale,'#111',12,600);
  fill(c,47*scale,749*scale,145*scale,17*scale,'#fff');nativeText(c,'message_demo.exe',48*scale,762*scale,'#111',12);
  t=Math.min(t,18.6);
  const visits=[[3.5,0],[6,1],[8.5,3],[10.8,2],[13,4],[15,1],[16.8,4]],visit=Math.max(0,visits.findLastIndex(([at])=>at<=t));
  const [start,index]=visits[visit],fn=sampleFunctions[index],elapsed=t-start,rename=t>=[5.15,7.65,12.45,8.5,13][index],decompiling=elapsed>=0&&elapsed<.36;
  const name=rename?fn.name:fn.raw;
  fill(c,6*scale,402*scale,188*scale,212*scale,'#fff');
  icon(c,'chevron',10*scale,407*scale,12,'#5e6268');nativeText(c,'Functions',28*scale,418*scale,'#222',12);
  sampleFunctions.forEach((entry,i)=>{
    const y=(438+i*22)*scale;
    if(i===index)fill(c,23*scale,y-14,167*scale,20,'#d8e7fa');
    icon(c,'file',29*scale,y-12,12,'#566fac');nativeText(c,entry.name,47*scale,y,'#263957',11.5);
  });
  fill(c,233*scale,94*scale,300*scale,21*scale,'#c3c3c3');nativeText(c,'Listing: message_demo.exe',237*scale,109*scale,'#111',13);
  fill(c,832*scale,94*scale,382*scale,21*scale,'#bac2d0');nativeText(c,'Decompile: '+name,834*scale,109*scale,'#fff',13);
  const top=119*scale,listingX=211*scale,codeX=814*scale,paneH=640*scale,scroll=55*travel(elapsed,.36,.9)+102*travel(elapsed,1.2,1.7);
  const selected=Math.max(3,Math.min(fn.code.length-3,3+Math.floor(Math.max(0,elapsed)*5))),codeScroll=Math.max(0,(fn.code.length+1)*17-paneH+36)*travel(elapsed,.85,1.7);
  fill(c,listingX,top,589*scale,paneH,'#fff');fill(c,codeX,top,610*scale,paneH,'#fff');
  c.save();c.beginPath();c.rect(listingX,top,583*scale,paneH);c.clip();
  fill(c,302*scale,top+167-scroll,491*scale,156,'#e1fcff');
  if(elapsed>=.36)fill(c,302*scale,top+282+selected*17-scroll-13,491*scale,17,'#bfdbf7');
  paste(c,assets['listing-'+index],302*scale,top-scroll,assets.scale*appLayout.ghidra.w/appLayout.ghidra.native);c.restore();
  c.save();c.beginPath();c.rect(codeX,top,608*scale,paneH);c.clip();
  if(decompiling)nativeText(c,'Decompiling '+fn.raw+'…',codeX+18,top+36,'#6e6e6e',13);
  else{
    if(elapsed>=.36){fill(c,codeX+25,top+selected*17+5-codeScroll,575*scale,18,'#e3edf9');fill(c,codeX+60,top+selected*17+5-codeScroll,56,18,'#fff0a4');}
    paste(c,assets[index===1&&t<16.1?'code-1-local':'code-'+index],codeX,top-codeScroll,assets.scale*appLayout.ghidra.w/appLayout.ghidra.native);
    if(rename){fill(c,codeX+28,top+22-codeScroll,565,19,'#fff');syntax(c,fn.code[0],codeX+30,top+37-codeScroll,13);}
  }
  c.restore();
  const consoleY=810*scale;
  fill(c,211*scale,consoleY,1215*scale,h-consoleY-33*scale,'#fff');
  if(t>=3.5){nativeText(c,'INFO  Analysis completed for message_demo.exe',220*scale,consoleY+24,'#4a545b',12,400,MONO);nativeText(c,rename&&[0,1,3].includes(visit)?'INFO  Renamed '+fn.raw+' to '+fn.name:'INFO  Selected function '+name,220*scale,consoleY+43,'#4a545b',12,400,MONO);}
  if(t>=8.5)nativeText(c,'INFO  '+(visit===2?'Following cross references to format_badge':visit>=4?'Call relationships resolved for present_message':'Synchronized Listing and Decompiler selection'),220*scale,consoleY+62,'#4a545b',12,400,MONO);
  if(t>=16.1)nativeText(c,'INFO  Renamed local_18 to preview',220*scale,consoleY+81,'#4a545b',12,400,MONO);
  fill(c,504*scale,h-25*scale,816*scale,22*scale,'#eee');nativeText(c,fn.address.toString(16)+'    '+name+'    |    x86:LE:64:default',512*scale,h-10,'#333',12);
  const localRename=visit===5&&elapsed>=.4&&elapsed<1.1,functionRename=[0,1,3].includes(visit)&&elapsed>=.95&&elapsed<1.65;
  if(localRename||functionRename)drawRenameDialog(c,fn,localRename,elapsed-(localRename ? .4 : .95),w,h);
  if((visit===2||visit===4)&&elapsed>=.55&&elapsed<1.75){
    const tree=visit===4,pw=tree?730:508,ph=tree?290:264,x=tree?330:(w-pw)/2,y=tree?350:(h-ph)/2;
    panel(c,x,y,pw,ph,()=>{
      if(tree){
        fill(c,x,y,pw,32,'#232b2d');nativeTraffic(c,x+16,y+16);
        nativeText(c,'Function Call Trees: present_message',x+84,y+22,'#b5bdc0',13,600);
        paneTitle(c,'Incoming References',x+8,y+40,235);paneTitle(c,'Outgoing References',x+250,y+40,pw-258,true);
        nativeText(c,'message_view',x+22,y+88,'#333',13,400,MONO);
        nativeText(c,'  present_message',x+22,y+110,'#333',13,400,MONO);
        nativeText(c,'present_message',x+269,y+88,'#333',13,600,MONO);
        fn.calls.forEach((callee,i)=>{
          const yy=y+112+i*28;
          if(i===Math.min(3,Math.floor((elapsed-.55)*4)))fill(c,x+263,yy-17,pw-280,24,'#d7e8fc');
          line(c,[[x+278,y+94],[x+278,yy-5],[x+296,yy-5]],'#9ba1a9',1);
          icon(c,'file',x+299,yy-14,13,'#566fac');nativeText(c,callee,x+319,yy,'#213f74',13,400,MONO);
        });
        nativeText(c,'4 outgoing calls',x+267,y+ph-18,'#666',12);
      }else{
        const reference=artworkIcons.get(c)?.['ref-ghidra-references'];
        if(reference){
          c.drawImage(reference,56,38,508,264,x,y,pw,ph);
          c.drawImage(reference,365,108,1,20,x+5,y+70,309,20);
        }else{
          fill(c,x,y,pw,32,'#232b2d');nativeTraffic(c,x+16,y+16);
          nativeText(c,'Edit    Help',x+8,y+48,'#111',13);fill(c,x+4,y+69,pw-8,22,'#aeb9cb');
          fill(c,x+4,y+94,pw-8,16,'#030506');nativeText(c,'Filter:',x+8,y+225,'#111',13);fill(c,x+57,y+212,380,18,'#fff');
        }
        fill(c,x+81,y+4,pw-89,24,'#232b2d');
        nativeText(c,'References to format_badge',x+84,y+21,'#b5bdc0',13,600);
        nativeText(c,'References to format_badge – 2 locations',x+8,y+85,'#fff',13);
        fill(c,x+4,y+111,pw-8,80,'#fff');
        const callers=sampleFunctions.filter(entry=>entry.calls.includes(fn.name));
        callers.forEach((caller,i)=>{
          const yy=y+124+i*20;
          if(i===Math.min(callers.length-1,Math.floor((elapsed-.55)*2)))fill(c,x+4,yy-13,pw-8,20,'#eef8ff');
          for(const [value,offset] of [[(caller.address+40).toString(16),8],[caller.name,161],['UNCONDITIONAL_CALL',336]])nativeText(c,value,x+offset,yy,'#111',12,400,MONO);
        });
      }
    },'#ededed',12);
  }
});}
function agentBadge(c,name,x,y){
  const source=artworkIcons.get(c)?.['ref-codex-working'];
  const crop={Atlas:[164,153],Lyra:[186,423],Nova:[208,423]}[name];
  if(source&&crop){c.save();c.globalCompositeOperation='lighten';c.drawImage(source,...crop,16,16,x,y,14,14);c.restore();return;}
  c.save();c.translate(x+7,y+7);c.lineWidth=1.1;
  if(name==='Atlas'){
    c.strokeStyle='#80d8bf';
    for(let i=0;i<6;i++){c.rotate(Math.PI/3);c.beginPath();c.moveTo(0,-2.2);c.bezierCurveTo(6,-6,8,1,3.2,4);c.lineTo(-1,1.5);c.stroke();}
  }else if(name==='Lyra'){
    for(let y=-1;y<=1;y++)for(let x=-1;x<=1;x++){
      const dx=(x-y)*2.1,dy=(x+y)*2.1;
      line(c,[[dx,dy-1.8],[dx+1.8,dy],[dx,dy+1.8],[dx-1.8,dy],[dx,dy-1.8]],'#b28bd4',1);
    }
  }else{
    for(let i=0;i<8;i++){const angle=i*Math.PI/4;circle(c,Math.cos(angle)*4.2,Math.sin(angle)*4.2,2.1,i%2?'#caa93b':'#e6c857');}
    circle(c,0,0,2.1,'#91813b');
  }
  c.restore();
}
function drawCodex(c,t){appFrame(c,'codex',(c,w,h)=>{
  const fresh=t<2.75||t>=28.9,composerY=h-116;
  const entrance=fresh?0:travel(researchPlayback(t),researchPlayback(2.75),researchPlayback(2.75)+.3),contentShift=(w/2-488)*(1-entrance);
  const refs=artworkIcons.get(c),empty=refs?.['ref-codex-empty'],workingImage=refs?.['ref-codex-working'],completedImage=refs?.['ref-codex-completed'],computerImage=refs?.['ref-codex-computer'];
  const firstDone=t>=18.55,cleanupStarted=t>=21.85,cleanupDone=t>=27.6;
  const crop=(image,sx,sy,sw,sh,x,y,dw=sw,dh=sh)=>c.drawImage(image,sx,sy,sw,sh,x,y,dw,dh);
  const computerMention=(x,y,color='#929baa')=>{
    if(computerImage)crop(computerImage,137,30,16,16,x,y-13);else icon(c,'copy',x,y-13,16,'#aecaff');
    nativeText(c,'Computer',x+20,y,color,14);return 20+c.measureText('Computer').width;
  };
  fill(c,0,0,w,h,'#181818');fill(c,0,0,w,43,'#191919');
  if(workingImage){
    crop(workingImage,45,38,101,22,10,12);crop(workingImage,160,39,20,20,110,13);
    crop(workingImage,205,41,18,17,163,14);crop(workingImage,1165,35,169,29,w-180,8);
  }else{nativeTraffic(c);icon(c,'sidebar',84,15,16,'#929292');icon(c,'new-chat',112,15,16,'#a7a7a7');icon(c,'folder-generic',163,14,16);nativeText(c,'Share',1191,28,'#929292',12);}
  nativeText(c,fresh?'New chat':'Message application review',188,28,'#e6e6e6',13,500);icon(c,'dots',423,15,17,'#909090');divider(c,0,43,w,'#363636');
  const agents=[
    {name:'Atlas',start:4.3,end:7.7},
    {name:'Lyra',start:4.3,end:18},
    {name:'Nova',start:11.2,end:18},
  ];
  const started=fresh?[]:agents.filter(agent=>t>=agent.start);
  const working=started.filter(agent=>t<agent.end||agent.name==='Lyra'&&t>=22&&t<26.4);
  if(!fresh){
    c.save();c.globalAlpha=entrance;c.translate((1-entrance)*28,0);
    round(c,962,55,302,423,20,'#2c2c2c');
    if(workingImage){
      crop(workingImage,1028,84,302,88,962,55);
      crop(workingImage,1041,181,100,23,975,152);
      crop(workingImage,1042,263,274,68,976,234);
      crop(workingImage,1041,344,82,26,975,315);crop(workingImage,1296,348,18,18,1230,319);
    }else{
      nativeText(c,'Outputs',977,85,'#999',14);nativeText(c,'Create a file or site',977,116,'#858585',14);icon(c,'plus',1233,71,16,'#999');
      nativeText(c,'Subagents',977,168,'#999',14);nativeText(c,'Computer Use',977,250,'#999',14);icon(c,'copy',977,272,17,'#ccc');nativeText(c,'Picture in Picture',1006,284,'#eee',14);
      nativeText(c,'Sources',977,333,'#999',14);icon(c,'plus',1233,319,16,'#999');
    }
    for(const y of [138,220,304])divider(c,977,y,271,'#414141');
    working.forEach((agent,i)=>agentBadge(c,agent.name,977+i*20,187));
    nativeText(c,`${working.length} working`,977+working.length*20,200,'#dedede',14);
    c.save();c.textAlign='right';nativeText(c,`${started.length-working.length} done`,1248,200,'#909090',14);c.restore();
    ['Ghidra MCP','Caido MCP','Playwright','messages.kawakatz.com'].forEach((label,i)=>{
      if(workingImage)crop(workingImage,1041,412,20,20,977,349+i*31,18,18);else icon(c,'branch',977,349+i*31,16,'#999');
      nativeText(c,label,1006,363+i*31,'#b6b6b6',14);
    });
    c.restore();
  }
  c.save();c.translate(contentShift,0);
  round(c,128,composerY,720,96,18,'#282828');
  if(empty){
    // Only the blank frame and native controls are sampled; reference messages never enter the artwork.
    crop(empty,360,1239,736,12,128,composerY,720,12);
    crop(empty,360,1251,12,74,128,composerY+12,12,72);
    crop(empty,370,1302,135,26,141,composerY+60);crop(empty,883,1302,133,27,620,composerY+60);
    crop(empty,1030,1304,17,23,771,composerY+62);
  }else{
    icon(c,'plus',144,composerY+64,17,'#b4b4b4');icon(c,'shield',174,composerY+65,15,'#e16d54');nativeText(c,'Full access',194,composerY+78,'#d47854',12);
    nativeText(c,'GPT-6 Astra',620,composerY+78,'#d4d4d4',12);nativeText(c,'Ultra',701,composerY+78,'#bb95e2',12,500);icon(c,'chevron',741,composerY+65,13,'#aaa');icon(c,'mic',771,composerY+63,18,'#c2c2c2');
  }
  const first='Find an RCE vulnerability.',cleanup='Please clean up ',firstTyping=t>=.6&&t<2.75,cleanupTyping=t>=20.75&&t<21.85;
  const cleanupQuery=cleanup+'@Computer',mentionSelected=cleanupTyping&&t>=21.6;
  const typed=firstTyping?first.slice(0,Math.floor(Math.min(1,(t-.6)/1.95)*first.length)):cleanupTyping?(mentionSelected?cleanup:cleanupQuery.slice(0,Math.floor(Math.min(1,(t-20.75)/.7)*cleanupQuery.length))):'';
  nativeText(c,typed||(fresh?'Ask anything':'Follow up'),147,composerY+29,typed?'#f0f0f0':'#909090',14);
  let caretX=147+c.measureText(typed).width;
  if(mentionSelected)caretX+=computerMention(caretX,composerY+29);
  if((firstTyping||cleanupTyping)&&Math.floor(t*2)%2===0)fill(c,caretX,composerY+16,1,16,'#eee');
  const busy=t>=2.75&&!firstDone||cleanupStarted&&!cleanupDone;
  if(busy&&workingImage)crop(workingImage,862,1285,32,32,808,composerY+57);
  else if(empty&&fresh&&!firstTyping)crop(empty,1058,1299,32,32,808,composerY+57);
  else{circle(c,824,composerY+73,13,'#eee');if(busy)round(c,819,composerY+68,10,10,2,'#303030');else icon(c,'up',816,composerY+65,16,'#303030');}
  if(fresh){if(empty)crop(empty,498,570,462,115,257,249);else{icon(c,'codex',470,249,36);c.save();c.textAlign='center';nativeText(c,'How can I help?',488,312,'#efefef',23,500);c.restore();}c.restore();return;}
  const playback=researchPlayback;
  const duration=(start,end)=>{
    const seconds=Math.max(0,Math.floor(playback(Math.min(t,end))-playback(start)+1e-6));
    return `${t>=end?'Worked':'Working'} for ${seconds>=60?Math.floor(seconds/60)+'m ':''}${seconds%60}s`;
  };
  const rows=[
    [2.75,'user',[first]],
    [2.75,'duration',[duration(2.75,18.55)],18.55],
    ...(firstDone?reviewResult:reviewProgress),
    [21.85,'user',[cleanup]],
    [21.85,'duration',[duration(21.85,27.6)],27.6],
    ...(cleanupDone?cleanupResult:cleanupProgress),
  ];
  const wrap=(paragraph,size,weight)=>{
    c.font=`${weight} ${size}px ${UI}`;
    const lines=[];let value='';
    for(const word of paragraph.split(/\s+/)){
      const next=value?value+' '+word:word;
      if(value&&c.measureText(next).width>720){lines.push(value);value=word;}else value=next;
    }
    if(value)lines.push(value);return lines;
  };
  const iconTop=(value,baseline)=>{
    c.font=`400 14px ${UI}`;const metrics=c.measureText(value);
    return baseline-((metrics.actualBoundingBoxAscent??10)-(metrics.actualBoundingBoxDescent??3))/2-7;
  };
  let y=77,bottom=y;
  const layout=rows.filter(([at])=>t>=at).map(([at,kind,content,end,activity])=>{
    let height=kind==='user'?65:kind==='duration'?44:kind==='actions'?40:38,lines=[];
    if(kind==='text'||kind==='result'){
      let offset=0;
      content.forEach((paragraph,index)=>{
        const size=kind==='result'&&index===0?15:14,weight=kind==='result'&&index===0?600:400;
        for(const value of wrap(paragraph,size,weight)){lines.push({value,offset,size,weight});offset+=23;}
        if(index<content.length-1)offset+=12;
      });
      height=offset+23;
    }
    if(kind==='status')end=codexSequence.find(([next])=>next>at)[0];
    const row={at,kind,content,end,activity,y,height,lines};y+=height;
    bottom=Math.max(bottom,row.y+height*travel(t,at,at+.35));return row;
  });
  c.save();c.beginPath();c.rect(124,55,728,composerY-72);c.clip();c.translate(0,-Math.max(0,bottom-(composerY-24)));
  for(const row of layout){
    c.save();c.globalAlpha=row.lines.length?1:travel(t,row.at,row.at+.14);
    if(row.kind==='user'){
      c.font=`400 14px ${UI}`;const mention=row.at===21.85,prefixWidth=c.measureText(row.content[0]).width,width=prefixWidth+(mention?20+c.measureText('Computer').width:0)+34;
      round(c,848-width,row.y,width,43,15,'#2e2e2e');nativeText(c,row.content[0],865-width,row.y+28,'#eee',14);
      if(mention)computerMention(865-width+prefixWidth,row.y+28,'#aab4c4');
    }else if(row.kind==='duration'){
      nativeText(c,row.content[0],128,row.y+17,'#989898',14);
      if(t>=row.end){
        const x=128+c.measureText(row.content[0]).width+5;
        if(completedImage)crop(completedImage,230,24,14,18,x,row.y+3);
        else{c.save();c.translate(x,row.y+4);c.rotate(-Math.PI/2);icon(c,'chevron',-12,0,12,'#818181');c.restore();}
      }
      divider(c,128,row.y+30,720,'#303030');
    }else if(row.kind==='status'){
      const active=t<row.end,source={search:[164,191],read:[164,1094],edit:[164,117],terminal:[164,973],computer:[1280,41]}[row.activity],top=iconTop(row.content[0],row.y+17);
      if(workingImage)crop(workingImage,...source,16,16,128,top,14,14);
      else icon(c,{read:'search',edit:'new-chat',computer:'copy'}[row.activity]||row.activity,128,top,14,'#818181');
      let ink='#848484';
      if(active){
        const width=c.measureText(row.content[0]).width,x=153+(playback(t)%2.4)/2.4*width;
        ink=c.createLinearGradient(x-width,0,x+width,0);
        for(const [stop,color] of [[0,'#d0d0d0'],[.15,'#777'],[.35,'#777'],[.5,'#d0d0d0'],[.65,'#777'],[.85,'#777'],[1,'#d0d0d0']])ink.addColorStop(stop,color);
      }
      nativeText(c,row.content[0],153,row.y+17,ink,14);
    }else if(row.kind==='agents'){
      const [names,detail]=row.content,top=iconTop(detail,row.y+17);
      names.forEach((name,i)=>agentBadge(c,name,128+i*20,top));
      nativeText(c,detail,134+names.length*20,row.y+17,'#999',14);
    }else if(row.kind==='actions'){
      if(completedImage)crop(completedImage,90,488,136,25,128,row.y+3);
      else ['copy','refresh','branch','download','new-chat'].forEach((name,i)=>icon(c,name,128+i*28,row.y+8,14,'#878787'));
    }else{
      let remaining=Math.floor(Math.max(0,playback(t)-playback(row.at))*17+1e-7);
      for(const entry of row.lines){
        const value=entry.value.slice(0,Math.max(0,remaining));remaining-=entry.value.length;
        if(value)nativeText(c,value,128,row.y+18+entry.offset,'#ededed',entry.size,entry.weight);
      }
    }
    c.restore();
  }
  c.restore();
  if(cleanupTyping&&!mentionSelected&&typed.includes('@')){
    const top=composerY-96;
    panel(c,128,top,720,84,()=>{
      round(c,140,top+12,696,60,7,'#3c3c3c');computerMention(152,top+36,'#f1f1f1');
      nativeText(c,'Interact with apps and websites on your computer.',172,top+59,'#a8a8a8',12);
      nativeText(c,'↵',809,top+41,'#c1c1c1',16);
    },'#2c2c2c',12);
  }
  c.restore();
});}
// Requests appear only after their illustrated Edge actions, on the shared operation clock.
const historyRows=[
  [10.65,'GET','/api/search?q=desk','200','application/json',1274,59],
  [10.9,'GET','/api/search?q=desk-preview','200','application/json',928,42],
  [11.05,'GET','/messages/desk-preview','200','text/html',4312,33],
  [11.1,'GET','/assets/messages.css','304','text/css',0,8],
  [11.15,'GET','/assets/app.js','304','text/javascript',0,12],
  [11.2,'GET','/api/channels/desk-preview','200','application/json',1216,31],
  [11.25,'GET','/api/members','200','application/json',948,27],
  [11.3,'GET','/api/messages?channel=desk-preview','200','application/json',3164,42],
  [11.45,'GET','/api/threads/desk-01','200','application/json',1876,37],
  [11.9,'GET','/api/threads/desk-01?before=20','200','application/json',2294,45],
  [12.75,'POST','/api/typing','204','application/json',0,14],
  [14.2,'POST','/api/messages','201','application/json',586,83],
  [14.65,'GET','/api/messages/scene-01/receipts','200','application/json',298,25],
  [15.1,'GET','/api/delivery/status','200','application/json',196,19],
  [15.55,'GET','/api/search?q=Hello','200','application/json',1628,48],
  [15.95,'GET','/api/search?q=Hello%20from%20the%20desk.','200','application/json',426,32],
  [16.4,'GET','/api/messages/scene-01','200','application/json',426,32],
].map(([at,method,path,status,type,bytes,latency],i)=>({at,method,path,status,type,bytes,latency,id:i+1}));
function httpLines(c,lines,x,y,size=13){lines.forEach((value,i)=>{nativeText(c,String(i+1),x,y+i*18,'#91959c',size-1,400,MONO);const colon=value.indexOf(':');if(i>0&&colon>0&&!value.trim().startsWith('"')){nativeText(c,value.slice(0,colon+1),x+25,y+i*18,'#e8c06c',size,600,MONO);nativeText(c,value.slice(colon+1),x+25+c.measureText(value.slice(0,colon+1)).width,y+i*18,'#e1e3e8',size,400,MONO);}else nativeText(c,value,x+25,y+i*18,i===0?'#91c8a6':value.includes('"')?'#bfcfab':'#dbdee4',size,400,MONO);});}
function emptyRequests(c,x,y,w,h,replay=false,response=false){
  c.save();c.textAlign='center';
  nativeText(c,response?'No response to display':replay?'No replay session selected':'No request to display',x+w/2,y+h/2,'#a1a2a6',14);
  nativeText(c,replay&&!response?'Select a replay session to replay requests.':response?'Select a request with a response to view it here.':'Select a request to view it here.',x+w/2,y+h/2+25,'#919499',13);
  c.restore();
}
function caidoDeleteMenu(c,replay){
  const image=artworkIcons.get(c)?.[replay?'ref-caido-replay-menu':'ref-caido-history-menu'];
  const [x,y,w,h]=replay?[508,221,175,136]:[701,247,191,463];
  if(image){
    c.save();c.beginPath();c.roundRect(x,y,w,h,5);c.clip();c.drawImage(image,x,y,w,h,x,y,w,h);
    if(replay){c.drawImage(image,550,345,116,5,542,325,129,20);nativeText(c,'Delete session (1)',544,340,'#f28c99',12);}
    c.restore();return;
  }
  round(c,x,y,w,h,5,'#25282f');
  const labels=replay?['Add session','Open all sessions','Rename','Delete session (1)']:['Copy URL','Save to file','Send to Replay','Send to Automate','Send to Findings…','Replay in browser','View response in browser','Highlight','Add in Scope','Out of Scope','Run workflow','Plugins','Delete…','Delete all…'];
  labels.forEach((label,i)=>nativeText(c,label,x+17,y+22+i*(replay?32:32.5),label.startsWith('Delete')?'#f28c99':'#e4e5e8',13));
}
function caidoDeleteDialog(c,w,h,replay){
  fill(c,56,70,w,h-32,'rgba(0,0,0,.38)');
  const image=artworkIcons.get(c)?.[replay?'ref-caido-replay-dialog':'ref-caido-history-dialog'];
  const [x,y,dw,dh]=replay?[689,534,534,170]:[740,534,433,170];
  if(image){
    c.save();c.beginPath();c.roundRect(x,y,dw,dh,6);c.clip();c.drawImage(image,x,y,dw,dh,x,y,dw,dh);
    if(replay){
      c.drawImage(image,711,590,450,10,711,558,450,29);c.drawImage(image,711,590,490,10,711,606,490,25);
      nativeText(c,'Are you sure you want to delete 1 session?',711,579,'#d2d3d6',16,600);
      nativeText(c,'You are about to permanently delete 1 session. This action cannot be undone.',711,625,'#c5c5c9',14);
    }
    c.restore();return;
  }
  round(c,x,y,dw,dh,6,'#25282f');
  nativeText(c,replay?'Are you sure you want to delete 1 session?':'Delete all entries in this table?',x+22,y+44,'#d2d3d6',15,600);
  nativeText(c,replay?'You are about to permanently delete 1 session. This action cannot be undone.':'All values associated with the requests in this table will be lost.',x+22,y+91,'#c5c5c9',13);
  nativeText(c,'Cancel',x+dw-173,y+138,'#babcc3',14);round(c,x+dw-114,y+116,93,33,5,replay?'#a72145':'#f28b99');nativeText(c,'Yes, delete',x+dw-102,y+138,replay?'#fff':'#27232a',14);
}
function drawCaido(c,t){appFrame(c,'caido',(c,w,h)=>{
  const replay=t>=17.3&&t<25.1,cleared=replay?t>=24.75:t>=26.4,refs=artworkIcons.get(c);
  const base=refs?.[replay?'ref-caido-replay':'ref-caido-history'];
  c.save();c.scale(w/1800,h/1130);c.translate(-56,-38);
  const blit=(key,x,y,width,height)=>{const image=refs?.[key];if(image)c.drawImage(image,x,y,width,height,x,y,width,height);return Boolean(image);};
  if(base){
    c.drawImage(base,56,38,1800,1130,56,38,1800,1130);
    c.drawImage(base,1679,82,7,26,1684,82,109,26);
  }else{
    fill(c,56,38,1800,1130,'#30343b');nativeTraffic(c,72,54);nativeText(c,'Caido',140,59,'#aaa',13,600);nativeText(c,'CΛIDO',81,105,'#c7795b',26);
    nativeText(c,'HTTP History',94,284,replay?'#bbb':'#e8ab46',14);nativeText(c,'Replay',94,375,replay?'#e8ab46':'#bbb',14);nativeText(c,'Request',replay?550:245,replay?236:514,'#ddd',14);nativeText(c,'Response',replay?1210:1058,replay?236:514,'#ddd',14);
  }
  nativeText(c,'messages',1689,100,'#ddd',13,500);
  if(t>=16.8&&t<17.3){circle(c,200,371,9,'#e25563');c.save();c.textAlign='center';c.textBaseline='middle';nativeText(c,'1',200,371,'#fff',11,600);c.restore();}
  if(replay){
    if(cleared){
      if(!base){nativeText(c,'Add a session to get started.',282,252,'#c6a15a',14);nativeText(c,'Enter a connection URL',586,190,'#93979d',14);nativeText(c,'History (0/0)  ⌄',1143,190,'#92969d',14);emptyRequests(c,534,255,658,834,true);emptyRequests(c,1195,255,659,834,false,true);}
    }else{
      // Keep a single completed preview session; opening Replay reveals its existing result.
      fill(c,535,119,184,40,'#30343b');
      round(c,538,123,57,32,4,'#49453e');c.strokeStyle='#d6a545';c.lineWidth=1;c.stroke();nativeText(c,'1',551,145,'#ddd',13);icon(c,'close',573,130,13,'#a6a7ad');
      fill(c,231,231,300,90,'#292c32');fill(c,232,232,298,29,'#53565d');fill(c,231,232,2,29,'#d6a545');nativeText(c,'1',286,252,'#ddd',14);icon(c,'dots',499,239,13,'#91949c');
      if(!blit('ref-caido-replay-menu',540,168,869,34)){round(c,540,168,499,34,4,'#25282e');round(c,1306,169,102,32,5,'#a92244');nativeText(c,'Send',1341,190,'#fff',14);}
      fill(c,579,172,419,26,'#25282e');nativeText(c,'https://messages.kawakatz.com',587,190,'#ddd',14);
      fill(c,1122,173,140,24,'#30343b');nativeText(c,'History (1/1)  ⌄',1141,190,'#bbb',14);
      blit('ref-caido-replay-menu',1057,215,119,33);blit('ref-caido-replay-menu',1639,215,199,33);
      fill(c,534,255,658,834,'#30343b');fill(c,1195,255,659,834,'#30343b');
      httpLines(c,['POST /scene/preview HTTP/1.1','Host: messages.kawakatz.com','Content-Type: application/json','X-Scene: desk-preview','','{','  "card": "calculator",','  "mode": "preview"','}'],544,272,13);
      httpLines(c,['HTTP/1.1 200 OK','Content-Type: application/json','X-Request-Id: desk-1072','','{','  "accepted": true,','  "preview": "calculator",','  "scene": "workspace"','}'],1207,272,13);
      nativeText(c,'586 bytes  |  83ms',1640,1112,'#c5c8d0',13);
      blit('ref-caido-replay-menu',535,1092,173,33);
    }
  }else{
    const all=cleared?[]:historyRows.filter(row=>row.at<=t).slice().reverse(),rows=all.slice(0,12);
    if(rows.length){
      fill(c,231,151,1623,252,'#30343b');
      rows.forEach((row,i)=>{
        const top=151+i*21,y=top+15;fill(c,231,top,1623,20,i%2?'#30343b':'#363a43');
        c.textAlign='left';nativeText(c,String(row.id),245,y,'#eee',14);
        c.font=`400 14px ${UI}`;let host='messages.kawakatz.com';while(c.measureText(host).width>121)host=host.slice(0,-2)+'…';nativeText(c,host,350,y,'#eee',14);
        let path=row.path;while(c.measureText(path).width>310)path=path.slice(0,-2)+'…';
        nativeText(c,row.method,491,y,'#eee',14);nativeText(c,path,603,y,'#eee',14);nativeText(c,row.status,937,y,'#eee',14);nativeText(c,String(row.bytes),1205,y,'#eee',14);nativeText(c,String(row.latency),1424,y,'#eee',14);
        nativeText(c,i===0?'just now':`${Math.max(1,Math.floor((t-row.at)*3.22))} s ago`,1466,y,'#ddd',14);
      });
      if(all.length>12){fill(c,1847,151,4,252,'#25282d');round(c,1847,151,4,252*12/all.length,2,'#727782');}
    }
    if(!base){
      if(!rows.length)nativeText(c,"You don't have any intercepted requests",892,252,'#e1e1e5',15,500);
      nativeText(c,'Waiting for a request…',349,474,'#bbb',14);
      emptyRequests(c,231,533,809,556);emptyRequests(c,1044,533,810,556,false,true);
    }
  }
  if(t>=23.75&&t<24.35)caidoDeleteMenu(c,true);
  if(t>=24.35&&t<24.75)caidoDeleteDialog(c,1800,1130,true);
  if(t>=25.4&&t<26)caidoDeleteMenu(c,false);
  if(t>=26&&t<26.4)caidoDeleteDialog(c,1800,1130,false);
  c.restore();
});}
function drawEdge(c,t,operating=false){appFrame(c,'edge',(c,w,h)=>{
  fill(c,0,0,w,h,'#25262e');fill(c,0,0,w,44,'#141414');fill(c,0,44,w,42,'#282828');
  const reference=artworkIcons.get(c)?.['ref-edge'],scale=w/1219;
  if(reference)c.drawImage(reference,56,38,1219,80,0,0,w,86);
  fill(c,148*scale,8,173*scale,27,'#333');nativeText(c,'Messages — Desk',150*scale,28,'#eee',13);
  fill(c,106*scale,48,762*scale,30,'#242424');nativeText(c,t>=11?'https://messages.kawakatz.com/inbox':'https://messages.kawakatz.com',108*scale,67,'#eee',14);
  const active=t>=11,channel=active?'desk-preview':'general';
  const searching=t>=10.5&&t<11||t>=15.3&&t<16.35,thread=t>=11.4&&t<12.45,details=t>=14.65&&t<15.3;
  const avatar=(x,y,size,initial,color,online=false)=>{
    round(c,x,y,size,size,size*.3,color);c.save();c.textAlign='center';nativeText(c,initial,x+size/2,y+size*.66,'#f4f0fc',size*.39,600);c.restore();
    if(online){circle(c,x+size-1,y+size-1,5.5,'#1d1e26');circle(c,x+size-1,y+size-1,3.5,'#77c6a4');}
  };
  // Keep the original browser chrome; the workspace below it is authored scene artwork.
  fill(c,0,86,64,h-86,'#14151b');fill(c,64,86,208,h-86,'#1d1e26');fill(c,271,86,1,h-86,'#33343d');
  round(c,0,110,3,24,2,'#c6bcf5');avatar(13,101,38,'D','#7363a9');
  divider(c,18,155,28,'#303039');avatar(15,172,34,'S','#394851');avatar(15,219,34,'B','#55404f');
  round(c,15,269,34,34,12,'#22272b');icon(c,'plus',24,278,16,'#86c4ae');
  icon(c,'grid',23,h-40,18,'#82858f');
  nativeText(c,'Desk Messages',82,115,'#eeedf4',16,650);icon(c,'chevron',245,103,13,'#a6a5b4');
  divider(c,64,139,208,'#2c2d36');
  [['search','Browse'],['branch','Activity'],['file','Saved']].forEach(([name,label],i)=>{icon(c,name,82,160+i*32,16,'#9493a4');nativeText(c,label,109,173+i*32,'#b4b3c2',13);});
  nativeText(c,'Channels',83,280,'#7e7e90',11,600);icon(c,'plus',246,270,12,'#79798a');
  ['general','desk-preview','build-log','links'].forEach((label,i)=>{
    const y=296+i*33,selected=label===channel;
    if(selected){round(c,73,y-4,190,31,6,'#3e3758');fill(c,73,y+3,2,17,'#b6a2ef');}
    nativeText(c,'#',84,y+17,selected?'#c8b8f6':'#6e6f80',17,400);
    nativeText(c,label,109,y+16,selected?'#f0eafb':'#a4a3b4',13,selected?600:400);
    if(!active&&i===1){round(c,235,y+1,18,18,5,'#514266');nativeText(c,'1',241,y+14,'#e2d2ff',11,600);}
  });
  nativeText(c,'Direct messages',83,470,'#7e7e90',11,600);icon(c,'plus',246,460,12,'#79798a');
  [['R','Riley','#516978'],['N','Nora','#806770'],['D','Desktop app','#4c7269']].forEach(([initial,name,color],i)=>{
    avatar(83,489+i*39,24,initial,color,true);nativeText(c,name,119,506+i*39,'#b8b6c6',13);
  });
  fill(c,64,h-64,207,64,'#191a21');avatar(80,h-48,30,'K','#6d5b97',true);
  nativeText(c,'kawakatz',121,h-34,'#e0dbe9',13,600);nativeText(c,'Available',121,h-18,'#8e8d9e',11);icon(c,'grid',241,h-36,16,'#92909f');
  fill(c,272,86,w-272,69,'#25262e');divider(c,272,154,w-272,'#363740');
  nativeText(c,'#',297,117,'#93909e',24,400);nativeText(c,channel,322,115,'#eeeaf4',18,600);
  nativeText(c,active?'Notes from the workspace, delivered to your desktop.':'Good ideas, work in progress, and everything in between.',298,138,'#93919f',12);
  ['#516978','#806770','#6d5b97'].forEach((color,i)=>avatar(1044+i*22,102,24,['R','N','K'][i],color));
  circle(c,1133,115,3,'#7fc7a7');nativeText(c,'3 online',1142,119,'#a5aba8',11);icon(c,'search',1229,105,18,'#aaa7b4');
  const message=(y,initial,name,color,time,body)=>{
    avatar(297,y,36,initial,color);nativeText(c,name,346,y+13,'#e8e2ef',14,600);const nameWidth=c.measureText(name).width;
    nativeText(c,time,356+nameWidth,y+13,'#797986',11);nativeText(c,body,346,y+38,'#c5c2cd',14);
  };
  if(!active){
    round(c,298,189,47,47,15,'#3a344a');nativeText(c,'#',311,223,'#c7b8e9',30,500);
    nativeText(c,'Welcome to Desk Messages',298,273,'#efebf4',23,650);
    nativeText(c,'A small place for notes from your desktop.',298,302,'#a4a1ae',14);
    divider(c,298,336,958,'#373840');round(c,733,325,88,22,11,'#25262e');nativeText(c,'Today',759,341,'#8d8a98',11,500);
    message(364,'R','Riley','#516978','10:20','The workspace is ready. Drop a note whenever inspiration strikes.');
    round(c,346,414,42,24,6,'#373343');icon(c,'check',354,420,13,'#c1ade9');nativeText(c,'2',374,431,'#bfb3d7',11);
    message(472,'N','Nora','#806770','10:23','A little space to build, share, and stay in touch.');
    avatar(346,529,20,'R','#516978');avatar(361,529,20,'K','#6d5b97');nativeText(c,'2 replies',391,544,'#b4a1de',12,500);nativeText(c,'Last reply 10:24',451,544,'#777582',11);
  }else{
    round(c,297,175,958,57,7,'#2c2c36');fill(c,297,187,2,32,'#8c78b8');icon(c,'file',311,185,13,'#9991af');
    nativeText(c,'Pinned by Riley',332,196,'#9e96af',11);nativeText(c,'A small update goes a long way.',312,217,'#cec6dd',13);
    divider(c,298,259,958,'#373840');round(c,733,248,88,22,11,'#25262e');nativeText(c,'Today',759,264,'#8d8a98',11,500);
    message(288,'R','Riley','#516978','10:24','Send a message to your desktop.');
    round(c,346,338,116,23,5,'#293833');circle(c,357,350,3,'#80bda1');nativeText(c,'Desktop connected',366,354,'#9cc3b1',10);
    if(thread)round(c,285,379,970,101,7,'#2d2b39');
    message(391,'N','Nora','#806770','10:25','Everything is connected. Your next note will show up there.');
    avatar(346,447,20,'R','#516978');nativeText(c,'1 reply',377,462,'#b4a1de',12,500);nativeText(c,'View thread',425,462,'#777582',11);
    if(t>=14.2){
      c.save();c.globalAlpha=travel(t,14.2,14.4);c.translate(0,(1-c.globalAlpha)*5);
      if(details)round(c,285,496,970,96,7,'#2c3039');
      message(508,'K','kawakatz','#6d5b97','10:26','Hello from the desk.');
      icon(c,t>=15?'check':'dots',346,561,12,t>=15?'#81bda4':'#858293');nativeText(c,t>=15?'Delivered':'Sending…',363,571,'#8e9b94',11);c.restore();
    }
  }
  const y=h-116,typing=active&&t>=12.7&&t<14.2;
  round(c,296,y,960,84,9,'#31323c');c.strokeStyle=typing?'#796799':'#44434f';c.lineWidth=1;c.stroke();
  const input=typing?'Hello from the desk.'.slice(0,Math.max(0,Math.floor((t-12.7)*16))):active&&t>=14.2?'Write a message…':`Message # ${channel}`;
  nativeText(c,input,315,y+30,typing?'#e5dfed':'#8f8b9d',14);
  if(typing&&Math.floor((t-12.7)*2)%2===0)fill(c,316+c.measureText(input).width,y+16,1,17,'#cbbce2');
  icon(c,'plus',315,y+54,16,'#a8a0b8');nativeText(c,'Aa',348,y+67,'#a8a0b8',14,500);
  circle(c,390,y+60,7,'#a8a0b8');circle(c,390,y+60,5.8,'#31323c');circle(c,387.5,y+58.2,.7,'#a8a0b8');circle(c,392.5,y+58.2,.7,'#a8a0b8');line(c,[[387.5,y+62],[390,y+63],[392.5,y+62]],'#a8a0b8',1);
  fill(c,413,y+49,1,22,'#4b4557');icon(c,'file',428,y+53,16,'#a8a0b8');
  round(c,1172,y+45,67,28,6,typing?'#8d72b5':'#514461');nativeText(c,'Send',1185,y+64,typing?'#fff':'#bfb0cf',12,600);
  nativeText(c,'Enter to send · Shift + Enter for a new line',315,h-13,'#73707f',10);
  if(thread){
    const x=w-425+(1-travel(t,11.4,11.53))*425;
    c.save();c.translate(x,0);fill(c,0,155,425,h-155,'#20212a');fill(c,0,155,1,h-155,'#45404f');
    nativeText(c,'Thread',22,188,'#eee9f5',17,600);nativeText(c,'# desk-preview',89,188,'#8d879c',12);icon(c,'close',386,173,17,'#aaa3b7');divider(c,0,208,425,'#36333f');
    avatar(22,231,30,'N','#806770');nativeText(c,'Nora',63,243,'#e8e2ef',13,600);nativeText(c,'10:25',104,243,'#797986',10);
    nativeText(c,'Everything is connected.',63,265,'#c5c2cd',13);nativeText(c,'Your next note will show up there.',63,284,'#c5c2cd',13);
    divider(c,22,311,381,'#36333f');nativeText(c,'3 replies',22,336,'#a399b5',11);
    const offset=travel(t,11.85,12.15)*36;
    c.save();c.beginPath();c.rect(1,353,423,h-510);c.clip();c.translate(0,-offset);
    [['R','Riley','#516978','10:25','The desktop connection looks good.'],['K','kawakatz','#6d5b97','10:25','Checking the message preview now.'],['N','Nora','#806770','10:26','Ready whenever you are.']].forEach(([initial,name,color,time,body],i)=>{
      const y=369+i*100;avatar(22,y,29,initial,color);nativeText(c,name,63,y+11,'#e8e2ef',13,600);const authorWidth=c.measureText(name).width;nativeText(c,time,73+authorWidth,y+11,'#797986',10);nativeText(c,body,63,y+36,'#bfb9cc',12);
    });c.restore();
    round(c,22,h-136,381,105,8,'#2d2c38');nativeText(c,'Reply in thread…',38,h-107,'#888195',13);icon(c,'plus',38,h-65,15,'#a8a0b8');icon(c,'play',370,h-65,15,'#a8a0b8');
    fill(c,417,358+offset,3,96,'#504859');c.restore();
  }
  if(details){
    panel(c,850,421,364,193,()=>{
      nativeText(c,'Delivery details',870,450,'#f0eaf8',14,600);icon(c,'close',1181,436,14,'#9d95ae');divider(c,870,466,324,'#48404f');
      nativeText(c,'Message ID',870,493,'#928a9f',12);nativeText(c,'msg_0142',1037,493,'#c6bfd0',12,400,MONO);
      nativeText(c,'Destination',870,523,'#928a9f',12);nativeText(c,'Desktop app',1037,523,'#c6bfd0',12);
      nativeText(c,'Status',870,553,'#928a9f',12);circle(c,1043,549,3,'#8ac9a9');nativeText(c,t>=15?'Delivered':'Sending…',1055,553,'#abd6bb',12);
      nativeText(c,t>=15?'Received just now':'Waiting for desktop…',870,587,'#8f859d',11);
    },'#302c3a',9);
  }
  if(searching){
    const history=t>=15.3,start=history?15.3:10.5,query=history?'Hello from the desk.':'desk-preview',typed=query.slice(0,Math.floor((t-start)*34));
    fill(c,272,155,w-272,h-155,'rgba(15,14,23,.28)');
    panel(c,459,164,676,history?326:295,()=>{
      round(c,477,183,640,45,7,'#24212f');icon(c,'search',491,196,18,'#b4a3d0');nativeText(c,typed,522,212,'#eee7f8',16);
      fill(c,523+c.measureText(typed).width,194,1,21,'#c7b2e8');round(c,1071,197,32,19,4,'#3d364a');nativeText(c,'esc',1077,210,'#9e92ad',10);
      nativeText(c,history?'Messages in # desk-preview':'Switch to a channel',479,257,'#9d90af',11,500);
      if(history){
        round(c,477,275,640,119,6,t>=16?'#41354f':'#34303e');avatar(492,291,31,'K','#6d5b97');nativeText(c,'kawakatz',537,304,'#e5dced',13,600);const authorWidth=c.measureText('kawakatz').width;nativeText(c,'10:26 · # desk-preview',547+authorWidth,304,'#9d90ab',11);
        nativeText(c,'Hello from the desk.',537,331,'#ded4e9',15);icon(c,'check',537,357,13,'#8ec5a7');nativeText(c,'Delivered to Desktop app',558,369,'#a0b8ab',11);
        nativeText(c,'1 result',479,423,'#92849f',11);nativeText(c,'Jump to message',975,461,'#b9a5d0',12);icon(c,'next',1095,446,15,'#b9a5d0');
      }else{
        ['desk-preview','general','build-log'].forEach((label,i)=>{const y=278+i*48;if(!i)round(c,477,y-2,640,42,6,'#443652');nativeText(c,'#',492,y+25,'#b9a7cb',19);nativeText(c,label,522,y+24,i?'#aca0b9':'#eee6f7',14,i?400:600);if(!i)nativeText(c,'Open channel ↵',1001,y+23,'#aa92c4',11);});
      }
    },'#302a3b',11);
  }
  if(operating&&t>=10.35&&t<16.7){
    const keys=[[10.35,908,200],[10.5,91,167],[10.9,659,299],[11.35,444,452],[11.4,445,452],[11.85,1103,572],[12.38,1247,181],[12.65,555,y+29],[14.18,1208,y+60],[14.6,425,565],[14.65,425,565],[15.22,1188,444],[15.3,1237,113],[16.1,701,325],[16.35,720,542],[16.65,930,584]];
    const i=keys.findIndex(key=>key[0]>t),a=keys[Math.max(0,i-1)],b=i<0?keys.at(-1):keys[i],p=travel(t,Math.max(a[0],b[0]-.18),b[0]);
    const x=a[1]+(b[1]-a[1])*p,cy=a[2]+(b[2]-a[2])*p;
    c.save();c.translate(x,cy);c.scale(.8,.8);c.shadowColor='#cfe8ff';c.shadowBlur=4;c.fillStyle='#eaf4ff';c.strokeStyle='#92c1ea';c.lineWidth=1;
    c.beginPath();[[0,0],[1,22],[7,16],[11,24],[14,22],[10,14],[19,13]].forEach(([px,py],j)=>j?c.lineTo(px,py):c.moveTo(px,py));c.closePath();c.fill();c.stroke();c.restore();
  }
});}
function manualCursor(c,t){
  if(!(t>=16.85&&t<18.05||t>=27.6&&t<29.18))return;
  const keys=t>=27.6?[[27.6,...screenPoint('edge',25,65)],[28.9,...screenPoint('codex',120,23)]]:[[16.85,...screenPoint('caido',470,120)],[17.05,...screenPoint('caido',300,17)],[17.3,...screenPoint('caido',70,263)],[17.8,...screenPoint('rdp',620,16)]];
  const next=keys.findIndex(([at])=>at>t),a=keys[next<0?keys.length-1:Math.max(0,next-1)],b=next<0?a:keys[next];
  const p=a===b?0:travel(t,Math.max(a[0],b[0]-.2),b[0]);
  c.save();c.globalAlpha=1-travel(t,29.02,29.18);c.translate(a[1]+(b[1]-a[1])*p,a[2]+(b[2]-a[2])*p);c.scale(.3,.3);
  c.fillStyle='#101010';c.strokeStyle='#ffffff';c.lineWidth=1.2;
  c.beginPath();[[0,0],[1,16],[5.2,12],[8.1,18.3],[10.6,17.1],[7.5,10.8],[13.2,10]].forEach(([x,y],i)=>i?c.lineTo(x,y):c.moveTo(x,y));c.closePath();c.fill();c.stroke();c.restore();
}
function cleanupCursor(c,t){
  if(t<21.85||t>=27.6)return;
  const keys=[
    [21.85,...screenPoint('codex',826,appLayout.codex.h*1280/558-47)],
    [22.05,...screenPoint('rdp',419,116)],[22.45,...screenPoint('rdp',1488,744)],
    [22.9,...screenPoint('ghidra',1300,15)],[23.45,...screenPoint('caido',700,17)],
    [23.75,...screenPoint('caido',385.707,138.953)],[24.35,...screenPoint('caido',459.093,233.944)],
    [24.75,...screenPoint('caido',937.813,493.009)],
    [25.1,...screenPoint('caido',69.973,189.196)],[25.4,...screenPoint('caido',558.08,162.504)],
    [26,...screenPoint('caido',631.467,511.065)],[26.4,...screenPoint('caido',894.293,493.009)],
    [26.9,...screenPoint('edge',600,22)],[27.2,...screenPoint('edge',25,65)],
  ];
  const next=keys.findIndex(key=>key[0]>t),a=keys[next<0?keys.length-1:Math.max(0,next-1)],b=next<0?a:keys[next];
  const p=a===b?0:travel(t,Math.max(a[0],b[0]-.28),b[0]);
  const x=a[1]+(b[1]-a[1])*p,y=a[2]+(b[2]-a[2])*p;
  c.save();c.globalAlpha=travel(t,21.85,21.95)*(1-travel(t,27.45,27.6));
  for(const key of keys.slice(1)){const dt=t-key[0];if(dt>=0&&dt<.18){c.strokeStyle=`rgba(159,212,255,${1-dt/.18})`;c.lineWidth=.8*.5;c.beginPath();c.arc(key[1],key[2],(3+dt*28)*.5,0,Math.PI*2);c.stroke();}}
  c.translate(x,y);c.scale(.5,.5);c.shadowColor='#d7ebff';c.shadowBlur=7*.5;c.fillStyle='#e5f2ff';c.strokeStyle='#82b9f1';c.lineWidth=.65;
  c.beginPath();[[0,0],[1,16],[5.2,12],[8.1,18.3],[10.6,17.1],[7.5,10.8],[13.2,10]].forEach(([px,py],i)=>i?c.lineTo(px,py):c.moveTo(px,py));c.closePath();c.fill();c.stroke();c.restore();
}
function drawStory(c,t,assets){
  const operation=researchOperationTime(t),operating=operationStages.some(({start,end})=>t>=start&&t<end);
  const ghidraTime=operation>=26.7?0:Math.min(operation,18.6),edgeTime=operation>=27.2?0:operation;
  drawRdp(c,operation,assets);drawGhidra(c,ghidraTime,assets);drawCodex(c,t>=28.9?0:t);
  if(operation>=17.05&&operation<26.9){drawEdge(c,edgeTime,operating);drawCaido(c,operation);}else{drawCaido(c,operation);drawEdge(c,edgeTime,operating);}
  if(operation>=17.8&&operation<22.9)drawRdp(c,operation,assets);
  if(operation>=22.9&&operation<23.45)drawGhidra(c,ghidraTime,assets);
  if(operating){manualCursor(c,operation);cleanupCursor(c,operation);}
}
function renderResearch(c,t,assets,restore){
  restore(0,0,desktopWidth,desktopHeight);
  const phase=t<=.6||t>=29.3?0:t;
  drawStory(c,phase,assets);
  const operation=researchOperationTime(phase),operating=operationStages.some(({start,end})=>phase>=start&&phase<end);
  macMenu(c,assets.coast,assets.date,assets.menuProgress>0?'Chrome':operating?desktopFocus.findLast(([at])=>at<=operation)[1]:'Codex');
  if(MAC_DOCK_ICON_KEYS.every(key=>assets.icons[key]))drawMacDock(c,assets.icons,researchDock,operation,assets.date,{chromeProgress:assets.menuProgress});
  return {changed:true};
}

export function createComputerScreens(coast=null,icons={},rdpImages={},initialWidth=5120){
  const maps={},rect=getMacDockItemRect('minimized-chrome',researchDock);
  const dockOrigin=Object.freeze({x:rect.x/desktopWidth,y:rect.y/desktopHeight,w:rect.w/desktopWidth,h:rect.h/desktopHeight});
  let state,previousBucket=0,disposed=false,date=new Date(),menuProgress=0;
  let second=Math.floor(date.getTime()/1000);
  function release(old){
    old.base.width=old.base.height=old.map.image.width=old.map.image.height=0;
    for(const image of Object.values(old.assets))if(image?.getContext)image.width=image.height=0;
  }
  function setResolution(name,width){
    if(disposed||name!=='research'||!Number.isFinite(width)||width<1||width>16384)return false;
    width=Math.max(512,Math.round(width/256)*256);
    const old=state;if(old?.map.image.width===width)return false;
    const w=desktopWidth,h=desktopHeight,scale=width/w,assets={scale,icons,date,rdpImages,coast,menuProgress};
    const ratio=appLayout.ghidra.w/appLayout.ghidra.native;
    sampleFunctions.forEach((fn,index)=>{
      assets['listing-'+index]=canvas(590*ratio,1040*ratio,c=>{c.scale(ratio,ratio);ghidraArtwork(c,fn,true);},scale,icons);
      assets['code-'+index]=canvas(590*ratio,800*ratio,c=>{c.scale(ratio,ratio);ghidraArtwork(c,fn,false);},scale,icons);
      if(index===1){const original={...fn,code:fn.code.map(value=>value.replace(/\bpreview\b/g,'local_18'))};assets['code-1-local']=canvas(590*ratio,800*ratio,c=>{c.scale(ratio,ratio);ghidraArtwork(c,original,false);},scale,icons);}
    });
    const base=canvas(w,h,c=>drawResearch(c,coast),scale,icons),image=canvas(w,h,null,scale,icons),c=image.getContext('2d');
    paste(c,base,0,0,scale);
    const restore=(x,y,width,height)=>c.drawImage(base,x*scale,y*scale,width*scale,height*scale,x,y,width,height);
    renderResearch(c,researchTime(previousBucket),assets,restore);
    // Release the old pixels before assigning the new source to the retained texture.
    if(old){old.map.dispose();release(old);}
    const map=old?.map??new THREE.CanvasTexture(image);map.image=image;map.colorSpace=THREE.SRGBColorSpace;
    if(!old)map.anisotropy=4;
    map.needsUpdate=true;maps.research=map;state={base,c,assets,restore,map};return true;
  }
  if(!setResolution('research',initialWidth))setResolution('research',5120);
  return {maps,setResolution,dockOrigin,setMenuProgress(value){
    if(disposed||!Number.isFinite(value))return false;
    value=Math.max(0,Math.min(1,value));if(value===menuProgress)return false;
    menuProgress=value;state.assets.menuProgress=value;
    renderResearch(state.c,researchTime(previousBucket),state.assets,state.restore);state.map.needsUpdate=true;return true;
  },refreshDate(value=new Date()){
    if(disposed||!(value instanceof Date)||!Number.isFinite(value.getTime()))return false;
    const next=Math.floor(value.getTime()/1000);if(next===second)return false;second=next;date=new Date(value.getTime());
    state.assets.date=date;renderResearch(state.c,researchTime(previousBucket),state.assets,state.restore);state.map.needsUpdate=true;return true;
  },update(elapsedMs){
    if(disposed||!Number.isFinite(elapsedMs)||elapsedMs<0)return false;
    const bucket=Math.floor(elapsedMs*30/1000+1e-7);if(bucket<=previousBucket)return false;previousBucket=bucket;
    renderResearch(state.c,researchTime(bucket),state.assets,state.restore);state.map.needsUpdate=true;return true;
  },dispose(){
    if(disposed)return;disposed=true;release(state);state.map.dispose();
  }};
}
