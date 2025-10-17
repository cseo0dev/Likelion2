using UnityEngine;

public class PlayerSmbSpawn : StateMachineBehaviour
{
    private PlayerController controller;

    public override void OnStateEnter(Animator animator, AnimatorStateInfo stateInfo, int layerIndex)
    {
        if (controller == null) controller = animator.GetComponent<PlayerController>();
    }

    public override void OnStateExit(Animator animator, AnimatorStateInfo stateInfo, int layerIndex)
    {
        controller.SetState(Constants.EPlayerState.Idle);
    }
}
