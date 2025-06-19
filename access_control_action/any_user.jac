import:jac from actions.jivas.access_control_action.user { User }

node AnyUser :User: {
    has name:str = "any"; 
}