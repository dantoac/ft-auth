from fasthtml.common import *

def toast_notification(dom_id: str = "notifications", message: str = "", type: str = "info",
                       position_x: str = "toast-end", position_y: str = "toast-top", timeout: int = 5000):
    return Div(_id=dom_id, _class=f"toast {position_x} {position_y} z-50", _hx_swap_oob="beforeend", _hx_swap="outerHTML")(
        #Div(_class="bg-slate-950/60")(
        Div(_class=f"alert alert-{type} drop-shadow-md drop-shadow-slate-950 flex flex-row justify-between",
            role="alert")(
            Span(f"{message}"),
            Button(I(_class="fas fa-xmark"),
                   _class=f"btn btn-xs btn-{type}",
                   _onclick="let el=me(this.parentNode); clearTimeout(el.timeout); el.remove()"),
            Script(f"""
            me(".alert").run((el)=>{{
              el.timeout = setTimeout(function(){{me(".alert").remove()}}, {timeout})
            }});
            """)
        ))
    #)
