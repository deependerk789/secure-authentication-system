(() => {
  "use strict";
  const root = document.getElementById("sa-help-agent");
  if (!root || root.dataset.initialized === "true") return;
  root.dataset.initialized = "true";
  const openBtn = document.getElementById("sa-help-open");
  const panel = document.getElementById("sa-help-panel");
  const closeBtn = document.getElementById("sa-help-minimize");
  const content = document.getElementById("sa-help-content");
  const form = document.getElementById("sa-help-form");
  const input = document.getElementById("sa-help-input");
  const tourCard = document.getElementById("sa-help-tour-card");
  const quickActions = document.getElementById("sa-help-quick-actions");

  const guides = {
    register:{title:"Create your account",steps:[
      ["Open Register","Use the Register or Create Account link in the navigation or login page."],
      ["Fill in your details","Enter the required details in the registration form. Use an email address you can access."],
      ["Submit the form","Review your details, then submit. If an error appears, read it and correct the highlighted fields."],
      ["Verify your email","Open the verification email and follow the link or instructions shown by SecureAuth. Check Spam/Junk if needed."]]},
    verify:{title:"Verify your email",steps:[
      ["Open your inbox","Check the inbox for the email address you used to register."],
      ["Check Spam/Junk","If the message is missing, check Spam/Junk and confirm the address was entered correctly."],
      ["Complete verification","Use the verification link or code provided by SecureAuth. Never share a verification code with another person."],
      ["Return to SecureAuth","Return to the site and sign in if prompted. If the link expired, use the site's resend option if available."]]},
    login:{title:"Login and OTP",steps:[
      ["Open Login","Go to the SecureAuth Login page."],
      ["Enter your credentials","Enter your registered email and password in the login form. The guide never needs to see these values."],
      ["Check your email","If two-factor authentication is enabled, look for the six-digit email OTP. Check Spam/Junk too."],
      ["Verify the code","Enter the code on the SecureAuth verification page. Codes expire; follow the site's login flow to request a fresh one if needed."]]},
    security:{title:"Dashboard and security",steps:[
      ["Open the dashboard","After logging in, use the dashboard navigation to find account and security options."],
      ["Review your account","Check the account details shown. Avoid sharing private account information in chats or screenshots."],
      ["Manage your password","Use Change Password if available. Choose a unique password and never share it with the help bot."],
      ["Review two-factor authentication","Open the two-factor/security section and follow the on-screen instructions. Keep recovery options safe."]]}
  };
  function currentPage(){
    const hint = `${root.dataset.helpPage||""} ${document.body.dataset.helpPage||""} ${location.pathname}`.toLowerCase();
    if(/register|signup|sign-up|create.?account/.test(hint)) return "register";
    if(/verify.?email|email.?verification|verification/.test(hint)) return "verify";
    if(/two.?factor|otp|login|sign-in|signin/.test(hint)) return "login";
    return "security";
  }
  function addMessage(text,who="bot"){
    const wrap=document.createElement("div"); wrap.className=`sa-help-message sa-help-message--${who}`;
    const p=document.createElement("p"); p.textContent=text; wrap.appendChild(p);
    content.insertBefore(wrap,tourCard); content.scrollTop=content.scrollHeight; return wrap;
  }
  function showPanel(){panel.hidden=false;openBtn.setAttribute("aria-expanded","true");openBtn.setAttribute("aria-label","Close SecureAuth help assistant");input.focus();}
  function hidePanel(){panel.hidden=true;openBtn.setAttribute("aria-expanded","false");openBtn.setAttribute("aria-label","Open SecureAuth help assistant");openBtn.focus();}
  openBtn.addEventListener("click",()=>panel.hidden?showPanel():hidePanel());
  closeBtn.addEventListener("click",hidePanel);

  function showTopic(topic,announce=true){
    const guide=guides[topic]||guides[currentPage()];
    if(announce)addMessage(`${guide.title}: I'll walk you through it step by step.`);
    tourCard.hidden=false;quickActions.hidden=true;let index=0;
    function render(){
      const [title,detail]=guide.steps[index];tourCard.replaceChildren();
      const kicker=document.createElement("div");kicker.className="sa-tour-kicker";kicker.textContent=`Guided tour · Step ${index+1} of ${guide.steps.length}`;
      const h=document.createElement("h3");h.textContent=title;
      const p=document.createElement("p");p.textContent=detail;
      const controls=document.createElement("div");controls.className="sa-help-tour-controls";
      if(index>0){const back=document.createElement("button");back.type="button";back.textContent="← Back";back.addEventListener("click",()=>{index--;render();});controls.appendChild(back);}
      const next=document.createElement("button");next.type="button";next.textContent=index===guide.steps.length-1?"Finish ✓":"Next →";
      next.addEventListener("click",()=>{if(index<guide.steps.length-1){index++;render();}else{tourCard.hidden=true;quickActions.hidden=false;addMessage("You're all set! Follow the actual page's instructions to complete the action. I won't submit forms or change account settings for you.");}});
      const skip=document.createElement("button");skip.type="button";skip.textContent="Skip";skip.addEventListener("click",()=>{tourCard.hidden=true;quickActions.hidden=false;});
      controls.append(next,skip);tourCard.append(kicker,h,p,controls);content.scrollTop=content.scrollHeight;
    } render();
  }
  root.querySelectorAll("[data-help-topic]").forEach(b=>b.addEventListener("click",()=>showTopic(b.dataset.helpTopic)));

  function answerFor(text){
    const q=text.toLowerCase();
    if(/register|create account|sign up|signup/.test(q))return ["register","To create an account, open Register, complete the required fields, submit the form, then follow the email-verification instructions."];
    if(/verify|verification|email/.test(q))return ["verify","Check your registered email inbox and Spam/Junk. Follow the verification link or instructions from SecureAuth. Never share verification codes."];
    if(/otp|one.?time|code|login|sign in|signin/.test(q))return ["login","Open Login and enter your registered credentials. If two-factor authentication is enabled, check your email for the six-digit OTP and enter it on the verification page."];
    if(/dashboard|password|security|2fa|two.?factor|account/.test(q))return ["security","After login, open the dashboard and find account/security settings. Use Change Password or the two-factor section if available; I won't ask for your password or OTP."];
    if(/hello|hi|hey|namaste/.test(q))return [null,"Hi! 👋 I'm your SecureAuth Guide. I can help with creating an account, verifying email, login/OTP, and dashboard security. Choose a topic below or ask me a question."];
    return [null,"I can help with account creation, email verification, login/OTP, and security settings. Choose one of the quick actions below. This version uses built-in guidance and does not connect to an external AI service."];
  }
  form.addEventListener("submit",event=>{
    event.preventDefault();const text=input.value.trim();if(!text)return;
    addMessage(text,"user");input.value="";
    const typing=document.createElement("div");typing.className="sa-help-message sa-help-message--bot sa-help-typing";typing.setAttribute("aria-label","Assistant is responding");typing.innerHTML="<i></i><i></i><i></i>";content.insertBefore(typing,tourCard);content.scrollTop=content.scrollHeight;
    window.setTimeout(()=>{typing.remove();const [topic,response]=answerFor(text);addMessage(response);if(topic&&/guide|show me|step|how to/.test(text.toLowerCase()))showTopic(topic,false);},450);
  });
  openBtn.addEventListener("click",()=>{if(!panel.hidden&&!root.dataset.greeted){root.dataset.greeted="true";addMessage(`You're on the ${currentPage().replace("_"," ")} area. Choose a topic above or ask me for help.`);}});
  document.addEventListener("keydown",event=>{if(event.key==="Escape"&&!panel.hidden)hidePanel();});
})();